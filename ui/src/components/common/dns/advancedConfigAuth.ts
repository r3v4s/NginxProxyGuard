// Whether a host's Advanced Config asks for a login, the way the server decides
// it (nginx/advanced_config_scan.go, AdvancedConfigHasAuth): an auth_request or
// auth_basic directive at any depth, outside comments and quotes. The host form
// uses it to warn that a list's domains can skip that login (#320).

const AUTH_DIRECTIVES = ['auth_request', 'auth_basic'];

/**
 * Calls visit with the name of every directive in text, at any depth, and stops
 * when visit returns true. Tokens follow nginx: "#" opens a comment and a quote
 * opens a string only at the start of a word; a word ends at whitespace, ";" or
 * "{" ("${" stays in the word); "\" escapes the next character.
 */
function someDirectiveName(text: string, visit: (name: string) => boolean): boolean {
  let atStart = true;
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n') {
      i++;
    } else if (c === '#') {
      while (i < text.length && text[i] !== '\n') i++;
    } else if (c === ';' || c === '{' || c === '}') {
      atStart = true;
      i++;
    } else if (c === '"' || c === "'") {
      for (i++; i < text.length && text[i] !== c; i++) {
        if (text[i] === '\\') i++;
      }
      i++;
      atStart = false;
    } else {
      const start = i;
      while (i < text.length) {
        const b = text[i];
        if (b === '\\') {
          i += 2;
          continue;
        }
        if (b === ' ' || b === '\t' || b === '\r' || b === '\n' || b === ';' || (b === '{' && !(i > start && text[i - 1] === '$'))) {
          break;
        }
        i++;
      }
      if (atStart && visit(text.slice(start, Math.min(i, text.length)))) return true;
      atStart = false;
    }
  }
  return false;
}

/** True when the Advanced Config holds auth_request or auth_basic anywhere. */
export function advancedConfigHasAuth(text: string | null | undefined): boolean {
  if (!text) return false;
  return someDirectiveName(text, (name) => AUTH_DIRECTIVES.includes(name));
}
