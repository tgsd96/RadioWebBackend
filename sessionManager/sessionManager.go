package sessionManager

import (
	"time"

	"github.com/gorilla/sessions"
)

type UserSession struct {
	ID             string
	GorillaSession *sessions.Session
	UID            int
	Expire         time.Time
}

func (us *UserSession) Create() {
	//us.ID = Password.GenerateSessionId(32)
}
