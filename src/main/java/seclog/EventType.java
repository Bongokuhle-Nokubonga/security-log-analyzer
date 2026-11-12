package seclog;

/** The kinds of security-relevant events the parsers understand. */
public enum EventType {
    /** SSH login with a wrong password or key. */
    LOGIN_FAILED,
    /** SSH login that succeeded. */
    LOGIN_SUCCESS,
    /** SSH connection for a username that does not exist on the server. */
    INVALID_USER,
    /** Packet dropped by the firewall. */
    FIREWALL_BLOCK,
    /** Packet allowed by the firewall. */
    FIREWALL_ALLOW
}
