// The tray delivery state has no Win32 types. Mount the production source here
// so the host-native client tier executes its retry tests.
#[path = "../../kerbridge-agent-windows/src/tray_delivery.rs"]
mod tray_delivery;
