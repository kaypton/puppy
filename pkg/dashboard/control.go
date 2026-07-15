package dashboard

// ControlType identifies a control request sent from the dashboard to the main
// goroutine.
type ControlType string

const (
	// ControlReloadConfig requests a hot reload of the configuration file.
	ControlReloadConfig ControlType = "reload_config"
	// ControlShutdown requests a graceful shutdown of the server.
	ControlShutdown ControlType = "shutdown"
	// ControlStopFrontend requests stopping a specific frontend.
	ControlStopFrontend ControlType = "stop_frontend"
	// ControlStartFrontend requests starting a specific frontend.
	ControlStartFrontend ControlType = "start_frontend"
)

// ControlRequest is a control command sent from the dashboard to the main
// goroutine via a channel. The main goroutine processes requests serially to
// avoid concurrent configuration mutations.
type ControlRequest struct {
	Type     ControlType
	Frontend string
	Reply    chan<- ControlResponse
}

// ControlResponse is the result of a control request, sent back from the main
// goroutine to the requester.
type ControlResponse struct {
	Success bool
	Message string
}
