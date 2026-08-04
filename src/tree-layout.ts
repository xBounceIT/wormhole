export const treeRowInset = 8;
export const treeSelectionSlotWidth = 16;
export const treeSlotGap = 6;
export const treeIndentStep = treeSelectionSlotWidth + treeSlotGap;
export const treeBranchRailWidth = 1;

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
