"""
Event Dispatcher - Pub/Sub event system for inter-module communication

Provides a decoupled way for modules to communicate via events.
"""

import logging
from typing import Callable, Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class EventType(Enum):
    """All event types in the system"""
    # Scan lifecycle
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"

    # Module lifecycle
    MODULE_LOADED = "module.loaded"
    MODULE_FAILED = "module.failed"
    MODULE_COMPLETED = "module.completed"

    # Finding events
    FINDING_DISCOVERED = "finding.discovered"
    FINDING_VERIFIED = "finding.verified"
    FINDING_UPDATED = "finding.updated"

    # Analysis events
    ANALYSIS_STARTED = "analysis.started"
    ANALYSIS_PROGRESS = "analysis.progress"
    ANALYSIS_COMPLETED = "analysis.completed"

    # Report events
    REPORT_GENERATED = "report.generated"

    # Integration events
    INTEGRATION_CALLED = "integration.called"
    INTEGRATION_FAILED = "integration.failed"


@dataclass
class Event:
    """Represents an event"""
    type: EventType
    source: str  # Module/component that emitted the event
    timestamp: datetime = None
    data: Dict[str, Any] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.data is None:
            self.data = {}
        if self.metadata is None:
            self.metadata = {}


class EventHandler:
    """Wrapper for event handler callback"""

    def __init__(self, callback: Callable,
                 event_type: Optional[EventType] = None,
                 async_mode: bool = False):
        self.callback = callback
        self.event_type = event_type
        self.async_mode = async_mode
        self.enabled = True

    def handle(self, event: Event) -> Any:
        """Execute the handler"""
        if not self.enabled:
            return None

        try:
            return self.callback(event)
        except Exception as e:
            logger.error(f"Error in event handler {self.callback.__name__}: {e}")
            return None

    def disable(self):
        """Disable this handler"""
        self.enabled = False

    def enable(self):
        """Enable this handler"""
        self.enabled = True


class EventDispatcher:
    """
    Central event dispatcher for the system.

    Implements pub/sub pattern for inter-module communication.
    """

    def __init__(self):
        self.handlers: Dict[EventType, List[EventHandler]] = {}
        self.event_history: List[Event] = []
        self.max_history = 1000
        self.logger = logger

    def subscribe(self, event_type: EventType,
                  callback: Callable,
                  async_mode: bool = False) -> EventHandler:
        """
        Subscribe to an event type.

        Args:
            event_type: EventType to subscribe to
            callback: Callable to execute when event fires
            async_mode: If True, handler is executed async (not yet implemented)

        Returns:
            EventHandler: Handler object (can be used to unsubscribe)
        """
        if event_type not in self.handlers:
            self.handlers[event_type] = []

        handler = EventHandler(callback, event_type, async_mode)
        self.handlers[event_type].append(handler)

        self.logger.debug(f"Handler {callback.__name__} subscribed to {event_type.value}")
        return handler

    def unsubscribe(self, event_type: EventType, handler: EventHandler):
        """Unsubscribe from an event type"""
        if event_type in self.handlers:
            if handler in self.handlers[event_type]:
                self.handlers[event_type].remove(handler)
                self.logger.debug(f"Handler unsubscribed from {event_type.value}")

    def emit(self, event: Event) -> List[Any]:
        """
        Emit an event.

        Args:
            event: Event object to emit

        Returns:
            List of handler return values
        """
        self.logger.info(f"Emitting event: {event.type.value} from {event.source}")

        # Store in history
        self._add_to_history(event)

        # Execute handlers
        results = []
        if event.type in self.handlers:
            for handler in self.handlers[event.type]:
                result = handler.handle(event)
                results.append(result)

        return results

    def emit_with_data(self, event_type: EventType, source: str,
                       data: Dict[str, Any] = None,
                       metadata: Dict[str, Any] = None) -> List[Any]:
        """
        Convenience method to emit event with data.

        Args:
            event_type: Type of event
            source: Source module/component
            data: Event data
            metadata: Additional metadata

        Returns:
            List of handler return values
        """
        event = Event(
            type=event_type,
            source=source,
            data=data or {},
            metadata=metadata or {}
        )
        return self.emit(event)

    def get_event_history(self, event_type: Optional[EventType] = None,
                          limit: int = 100) -> List[Event]:
        """Get event history"""
        if event_type is None:
            return self.event_history[-limit:]
        else:
            return [e for e in self.event_history if e.type == event_type][-limit:]

    def clear_history(self):
        """Clear event history"""
        self.event_history.clear()

    def get_handler_count(self, event_type: Optional[EventType] = None) -> int:
        """Get number of handlers for an event type"""
        if event_type is None:
            return sum(len(handlers) for handlers in self.handlers.values())
        return len(self.handlers.get(event_type, []))

    def _add_to_history(self, event: Event):
        """Add event to history (with size limit)"""
        self.event_history.append(event)
        if len(self.event_history) > self.max_history:
            self.event_history.pop(0)

    def __repr__(self) -> str:
        return f"<EventDispatcher with {self.get_handler_count()} handlers>"


# Global instance
_global_dispatcher: Optional[EventDispatcher] = None


def get_dispatcher() -> EventDispatcher:
    """Get the global event dispatcher instance"""
    global _global_dispatcher
    if _global_dispatcher is None:
        _global_dispatcher = EventDispatcher()
    return _global_dispatcher


def set_dispatcher(dispatcher: EventDispatcher):
    """Set a custom event dispatcher"""
    global _global_dispatcher
    _global_dispatcher = dispatcher
