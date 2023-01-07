

Users express their preferences (who to transact with, what actions are allowed, what tokens are accepted, etc) in VPs, and VPs check proposed state transitions to ensure that the user requirements are satisfied.

### UserVP
#### sendVP/recvVP
Users define their long-term preferences with `sendVP` and `recvVP`. Every transaction the user is involved into has to be approved by the user's VP in order to be considered valid.
* `SendVP` defines the conditions on which notes can be sent (e.g. signature check)
* `RecvVP` defines the conditions on which a note can be received by the user (e.g. sender whitelist)
