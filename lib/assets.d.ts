// The hub imports its static assets `with { type: 'file' }` (server.ts): the
// import resolves to a path string — on disk under `bun server.ts`, embedded
// in the binary under `bun build --compile`. These declarations give those
// imports that shape; TypeScript would otherwise try to type them as modules.
// ('*.html' is deliberately absent: bun-types already declares it, as
// HTMLBundle, so server.ts casts that one import instead.)
declare module '*.css' {
  const path: string;
  export default path;
}
declare module '*.js' {
  const path: string;
  export default path;
}
declare module '*.js.map' {
  const path: string;
  export default path;
}
