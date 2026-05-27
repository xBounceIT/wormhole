-- 0007_nodes_parent_sort_index: cover tree loads ordered by parent + user sort.

CREATE INDEX IF NOT EXISTS IX_Nodes_ParentId_SortOrder_Name
ON Nodes(ParentId, SortOrder, Name);
