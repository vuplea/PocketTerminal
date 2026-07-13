import { SESSION_PROTOCOL } from '../lib/protocol';
import { CliError, env, isWindows, readSecretFromStdin } from './config';
import { CREDENTIAL_TARGET, writeCredential } from './credential';
import { normalizeHubUrl, warnIfCleartext } from './link';

// `pt set-password` — store the workstation password in Windows Credential
// Manager, where hosts and the launcher read it from, instead of an
// environment variable. Piped input (the installer) or a hidden prompt. The
// password is proved against the configured hub before it is stored: a wrong
// one written here would leave the launcher silently redialing forever.

export async function setPassword(): Promise<void> {
  if (!isWindows) {
    throw new CliError('set-password uses Windows Credential Manager; on this platform set POCKETTERM_WORKSTATION_PASSWORD instead');
  }
  const password = process.stdin.isTTY
    ? await promptHidden('Workstation password: ')
    : await readSecretFromStdin();
  if (password.length === 0) throw new CliError('no password given');
  await verifyPassword(password);
  writeCredential(password);
  console.log(`Stored the workstation password in Credential Manager (generic credential "${CREDENTIAL_TARGET}").`);
}

// The hub gates /session upgrades on the workstation password (lib/auth.ts),
// so one dial proves it end-to-end — the same gate every session and launcher
// link passes. No register frame is sent, so the probe creates nothing on the
// hub; it upgrades, proves the password, and closes.
function verifyPassword(password: string): Promise<void> {
  if (env.hubUrl.length === 0) {
    console.log('POCKETTERM_HUB_URL is not set; storing the password unverified.');
    return Promise.resolve();
  }
  const normalized = normalizeHubUrl(env.hubUrl);
  // A cleartext hub URL puts the password readable on the wire right here —
  // say so before sending it, the same warning the link prints.
  warnIfCleartext(normalized);
  const url = `${normalized}/session`;
  return new Promise((resolve, reject) => {
    let ws: WebSocket;
    try {
      ws = new WebSocket(url, [SESSION_PROTOCOL, Buffer.from(password, 'utf8').toString('base64url')]);
    } catch (err) {
      return reject(new CliError(`could not reach the hub to verify the password (${url}): ${(err as Error).message}`));
    }
    const timer = setTimeout(() => {
      ws.terminate();
      reject(new CliError(`could not reach the hub to verify the password (${url}): timed out`));
    }, 10 * 1000);
    ws.onopen = () => {
      clearTimeout(timer);
      resolve();
      ws.close();
    };
    // A rejected upgrade surfaces as a close without an open; the HTTP status
    // (wrong password? lockout?) is not visible at this layer, so the message
    // names both. If onopen already resolved, this reject is a no-op.
    ws.onclose = (event) => {
      clearTimeout(timer);
      reject(new CliError('the hub rejected this password or is unreachable'
        + ` (${url}, close code ${event.code}${event.reason ? ` ${JSON.stringify(event.reason)}` : ''}) — not stored`));
    };
  });
}

// Bytes are scanned for the control keys (safe: UTF-8 continuation bytes are
// all >= 0x80, so they can never look like one) while the text between them
// goes through a streaming decoder — building the string byte-by-byte would
// turn a multi-byte password like "pässword" into mojibake that then fails
// hub auth despite being typed correctly.
function promptHidden(prompt: string): Promise<string> {
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let buffer = '';
    const decoder = new TextDecoder();
    const finish = () => {
      process.stdin.off('data', onData);
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdout.write('\n');
    };
    const onData = (chunk: Buffer) => {
      let start = 0;
      const takeText = (end: number) => {
        if (end > start) buffer += decoder.decode(chunk.subarray(start, end), { stream: true });
        start = end + 1;
      };
      for (let i = 0; i < chunk.length; i++) {
        const byte = chunk[i]!;
        if (byte === 0x0d || byte === 0x0a) { // Enter
          takeText(i);
          finish();
          resolve(buffer);
          return;
        }
        if (byte === 0x03) { // Ctrl-C: raw mode swallows the signal, so honor it here
          finish();
          reject(new CliError('cancelled'));
          return;
        }
        if (byte === 0x08 || byte === 0x7f) { // Backspace: drop one code point
          takeText(i);
          buffer = [...buffer].slice(0, -1).join('');
        } else if (byte < 0x20) { // other control keys: ignore
          takeText(i);
        }
      }
      takeText(chunk.length);
    };
    process.stdin.on('data', onData);
  });
}
