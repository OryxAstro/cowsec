package auth

import "github.com/go-chi/chi/v5"

// Routes mounts the sign-in API (login, 2FA, enrolment, session, audit) under r.
func (s *Service) Routes(r chi.Router) {
	r.Get("/config", s.HandleConfig)
	r.Post("/login", s.HandleLogin)
	r.Post("/verify", s.HandleVerify)
	r.Post("/enroll", s.HandleEnroll)
	r.Get("/me", s.HandleMe)
	r.Post("/logout", s.HandleLogout)
	r.Post("/totp/reset", s.HandleResetTOTP)
	r.Get("/audit", s.HandleAudit)
}
