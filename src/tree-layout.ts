export const treeRowInset = 8;
export const treeSelectionSlotWidth = 16;
export const treeSlotGap = 6;
export const treeIndentStep = treeSelectionSlotWidth + treeSlotGap;
export const treeBranchRailWidth = 1;
// Reserve space for the checkbox, disclosure, protocol icon, label and right inset.
export const treeRowContentWidth = 112;

export type TreeBranchGeometry = {
  left: number;
  width: number;
  connectorLeft: number;
  connectorWidth: number;
};

export type TreeRowGeometry = {
  paddingLeft: number;
  branch: TreeBranchGeometry | null;
};

export function getTreeRowGeometry(depth: number): TreeRowGeometry {
  if (!Number.isInteger(depth) || depth < 0) {
    throw new RangeError('Tree depth must be a non-negative integer.');
  }

  const paddingLeft = treeRowInset + depth * treeIndentStep;
  if (depth === 0) return { paddingLeft, branch: null };

  const left = treeRowInset + (depth - 1) * treeIndentStep + treeSelectionSlotWidth / 2;
  // Connectors terminate at the selection slot instead of continuing beneath the
  // checkbox toward the disclosure/protocol icon rail.
  const width = paddingLeft - left;
  return {
    paddingLeft,
    branch: {
      left,
      width,
      connectorLeft: left + treeBranchRailWidth,
      connectorWidth: width - treeBranchRailWidth,
    },
  };
}

export function getTreeRowStyles(depth: number) {
  const geometry = getTreeRowGeometry(depth);
  const inset = (value: number) => `min(${value}px, calc(100% - ${treeRowContentWidth}px))`;
  const paddingLeft = inset(geometry.paddingLeft);
  if (!geometry.branch) return { paddingLeft, branch: null };

  // Saturated indentation still connects to the parent's checkbox, even when the
  // horizontal connector must run back toward the child's selection slot.
  const parentInset = inset(geometry.paddingLeft - treeIndentStep);
  const left = `calc(${parentInset} + ${treeSelectionSlotWidth / 2}px)`;
  return {
    paddingLeft,
    branch: {
      left,
      connectorLeft: `min(${paddingLeft}, calc(${left} + ${treeBranchRailWidth}px))`,
      connectorWidth: `max(calc(${paddingLeft} - ${left} - ${treeBranchRailWidth}px), calc(${left} - ${paddingLeft}))`,
    },
  };
}
