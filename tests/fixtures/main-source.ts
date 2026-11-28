import { parse } from '@babel/parser';

export function mainSyntax(source: string, jsx = false) {
  return parse(source, {
    sourceType: 'module',
    plugins: jsx ? ['typescript', 'jsx'] : ['typescript'],
  });
}
export function visitSyntax(node: any, visit: (node: any) => void): void {
  if (!node || typeof node !== 'object') return;
  if (typeof node.type === 'string') visit(node);
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) {
      for (const child of value) visitSyntax(child, visit);
    } else if (value && typeof value === 'object') visitSyntax(value, visit);
  }
}
const text = (source: string, node: any): string => source.slice(node.start, node.end);
export function ipcRegistration(source: string, channel: string, guardOnly = false): string {
  const file = mainSyntax(source),
    found: any[] = [];
  visitSyntax(file, (node) => {
    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      node.callee.object.name === 'ipcMain' &&
      node.callee.property.name === 'handle' &&
      node.arguments[0]?.value === channel
    )
      found.push(node);
  });
  if (found.length !== 1) throw Error(`Expected exactly one ${channel} handler`);
  if (!guardOnly) return text(source, found[0]) + ';';
  const callback = found[0].arguments[1],
    guard = callback.body?.body?.[0];
  if (callback.type !== 'ArrowFunctionExpression' || guard?.type !== 'IfStatement')
    throw Error(`Missing leading protected guard for ${channel}`);
  // Exercise the actual newly added guard. Unchanged legacy bodies retain
  // their existing tests and an observable fallback in this focused harness.
  return `ipcMain.handle('${channel}', async (${callback.params.map((p: any) => text(source, p)).join(',')}) => {
    ${text(source, guard)}
    return 'legacy';
  });`;
}
export function declarations(source: string, names: readonly string[]): string {
  const selected: string[] = [],
    matched = new Set<string>();
  for (const node of mainSyntax(source).program.body) {
    const item = node as any;
    const name =
      item.type === 'FunctionDeclaration'
        ? item.id?.name
        : item.type === 'VariableDeclaration'
          ? item.declarations.find(
              (d: any) => d.id.type === 'Identifier' && names.includes(d.id.name),
            )?.id.name
          : undefined;
    if (name && names.includes(name)) {
      matched.add(name);
      selected.push(text(source, node));
    }
  }
  if (matched.size !== names.length) throw Error('Missing requested application declarations');
  return selected.join('\n');
}
