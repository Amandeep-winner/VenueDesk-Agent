"""Windows Service wrapper for VenueDesk Agent."""

import logging
import os
import sys
import time
from pathlib import Path

logger = logging.getLogger("venuedesk.service")

# If pywin32 is installed, allow running as native Windows Service
try:
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class VenueDeskService(win32serviceutil.ServiceFramework):
        _svc_name_ = "VenueDeskAgent"
        _svc_display_name_ = "VenueDesk Endpoint Agent"
        _svc_description_ = "VenueDesk endpoint inventory, telemetry, and security lifecycle agent."

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = win32event.CreateEvent(None, 0, 0, None)
            self.is_running = True

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stop_event)
            self.is_running = False

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            self.main()

        def main(self):
            config_path = Path("C:/ProgramData/VenueDesk/config.toml")
            os.environ["VENUEDESK_CONFIG"] = str(config_path)

            from agent.config import AgentConfig

            cfg = AgentConfig.load(config_path)
            logger.info("Starting VenueDesk Windows Service with state dir %s", cfg.state_dir)

            # Keep service alive checking stop event
            while self.is_running:
                rc = win32event.WaitForSingleObject(self.stop_event, 5000)
                if rc == win32event.WAIT_OBJECT_0:
                    break

except ImportError:
    # Standalone daemon mode fallback when pywin32 service manager is not bound
    def run_standalone():
        config_path = Path("C:/ProgramData/VenueDesk/config.toml")
        if not config_path.exists():
            config_path = Path("config.toml")

        from agent.config import AgentConfig

        cfg = AgentConfig.load(config_path)
        logger.info("Starting VenueDesk Agent background runner with state dir: %s", cfg.state_dir)
        while True:
            time.sleep(60)

    if __name__ == "__main__":
        run_standalone()


if __name__ == "__main__":
    if "win32serviceutil" in sys.modules:
        win32serviceutil.HandleCommandLine(VenueDeskService)
    else:
        run_standalone()
