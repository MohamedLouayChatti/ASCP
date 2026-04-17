class ASCPException(Exception):
    """Base exception for ASCP integration."""
    pass

class ApprovalRequiredError(ASCPException):
    """Raised when a tool execution requires human approval."""
    def __init__(self, tool_name: str, arguments: dict, message: str):
        self.tool_name = tool_name
        self.arguments = arguments
        super().__init__(message)
