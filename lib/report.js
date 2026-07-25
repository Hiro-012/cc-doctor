const SEVERITY_ORDER = { error: 0, warn: 1, info: 2 };

export class Report {
  constructor() {
    this.findings = [];
  }

  add(severity, check, message, file) {
    if (!(severity in SEVERITY_ORDER)) {
      throw new Error(`Unknown severity: ${severity}`);
    }
    this.findings.push({ severity, check, message, file });
  }

  error(check, message, file) {
    this.add('error', check, message, file);
  }

  warn(check, message, file) {
    this.add('warn', check, message, file);
  }

  info(check, message, file) {
    this.add('info', check, message, file);
  }

  merge(other) {
    this.findings.push(...other.findings);
  }

  sorted() {
    return [...this.findings].sort(
      (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    );
  }

  hasErrors() {
    return this.findings.some((f) => f.severity === 'error');
  }

  counts() {
    return this.findings.reduce(
      (acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      },
      { error: 0, warn: 0, info: 0 }
    );
  }
}
