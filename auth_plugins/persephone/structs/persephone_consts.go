package structs

const (
	PersephoneVersion       = "v1"
	SignatureAlgorithmEd448 = "Ed448"
)

const (
	PspCmdInitiateProtocol = "PSP_INITIATE_PROTOCOL"

	PspCmdOpaqueInitiateOpaque = "PSP_INITIATE_OPAQUE"
	PspCmdOpaqueExecute        = "PSP_OPAQUE_EXECUTE"

	PspCmdHydrateInitiateHydrate = "PSP_INITIATE_HYDRATE"
	PspCmdHydrateExecute         = "PSP_HYDRATE_EXECUTE"
)
