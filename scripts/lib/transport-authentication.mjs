/** Redact only HTTP URL authentication; keep paths, names, queries and other text. */
export function redactTransportAuthentication(text) {
  return text.replace(/https?:\/\/[^\s"<>\\]+/gu, (value) => {
    try {
      const parsed = new URL(value);
      if (!parsed.username && !parsed.password) return value;
      const start = value.indexOf("://") + 3;
      const tail = value.slice(start),
        end = tail.search(/[/?#]/u);
      const authority = end < 0 ? tail : tail.slice(0, end);
      return (
        value.slice(0, start) +
        authority.slice(authority.lastIndexOf("@") + 1) +
        (end < 0 ? "" : tail.slice(end))
      );
    } catch {
      return value;
    }
  });
}
