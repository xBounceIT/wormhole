package localvault

// ImportTimes carries native migration provenance. Values must use the stored
// aggregate's canonical UTC format; ordinary editors do not accept these fields.
type ImportTimes struct {
	CreatedAt string
	UpdatedAt string
}
