package route

import (
	"net/http"
	"app/controller"
	"app/route/middleware/acl"
	hrw "app/route/middleware/httprouterwrapper"
	log "app/route/middleware/logrequest"
	pprof "app/route/middleware/pprofhandler"
	"app/shared/session"
	"github.com/gorilla/context"
	csrf "github.com/josephspurrier/csrfbanana"
	router "github.com/julienschmidt/httprouter"
	"github.com/justinas/alice"
)

// Load returns the routes and middleware
func Load() http.Handler {
	return middleware(routes())
}

// LoadHTTPS returns the HTTP routes and middleware
func LoadHTTPS() http.Handler {
	return middleware(routes())
}

// LoadHTTP returns the HTTPS routes and middleware
func LoadHTTP() http.Handler {
	return middleware(routes())

	// Uncomment this and comment out the line above to always redirect to HTTPS
	//return http.HandlerFunc(redirectToHTTPS)
}

// Optional method to make it easy to redirect from HTTP to HTTPS
func redirectToHTTPS(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "https://"+req.Host, http.StatusMovedPermanently)
}

func routes() *router.Router {
	r := router.New()

	// Set 404 handler
	r.NotFound = alice
		.New()
		.ThenFunc(controller.Error404)

	// Serve static files, no directory browsing
	r.GET("/static/*filepath", hrw.Handler(
		alice
			.New()
			.ThenFunc(controller.Static)
		)
	)

	// Home page
	r.GET("/", hrw.Handler(
        alice
        	.New()
			.ThenFunc(controller.IndexGET)
		)
	)

	// Login
	r.GET("/login", hrw.Handler(
        alice
           	.New(acl.DisallowAuth)
			.ThenFunc(controller.LoginGET)
		)
	)
	r.POST("/login", hrw.Handler(
        alice
			.New(acl.DisallowAuth)
			.ThenFunc(controller.LoginPOST)
		)
	)
	r.GET("/logout", hrw.Handler(
        alice
			.New()
			.ThenFunc(controller.LogoutGET)
		)
	)

	// Register
	r.GET("/register", hrw.Handler(
        alice
			.New(acl.DisallowAuth)
			.ThenFunc(controller.RegisterGET)
		)
	)
	r.POST("/register", hrw.Handler(
        alice
			.New(acl.DisallowAuth)
			.ThenFunc(controller.RegisterPOST)
		)
	)

	// About
	r.GET("/about", hrw.Handler(
        alice
			.New()
			.ThenFunc(controller.AboutGET)
		)
	)

	// Notepad
	r.GET("/notepad", hrw.Handler(
        alice
			.New(acl.DisallowAnon)
			.ThenFunc(controller.NotepadReadGET)
		)
	)
	r.GET("/notepad/create", hrw.Handler(
        alice
			.New(acl.DisallowAnon)
			.ThenFunc(controller.NotepadCreateGET)
		)
	)
	r.POST("/notepad/create", hrw.Handler(
        alice
			.New(acl.DisallowAnon)
			.ThenFunc(controller.NotepadCreatePOST)
		)
	)
	r.GET("/notepad/update/:id", hrw.Handler(
        alice
			.New(acl.DisallowAnon)
			.ThenFunc(controller.NotepadUpdateGET)
		)
	)
	r.POST("/notepad/update/:id", hrw.Handler(
        alice
			.New(acl.DisallowAnon)
			.ThenFunc(controller.NotepadUpdatePOST)
		)
	)
	r.GET("/notepad/delete/:id", hrw.Handler(
        alice
			.New(acl.DisallowAnon)
			.ThenFunc(controller.NotepadDeleteGET)
		)
	)

	// Enable Pprof
	r.GET("/debug/pprof/*pprof", hrw.Handler(
        alice
			.New(acl.DisallowAnon)
			.ThenFunc(pprof.Handler)
		)
	)

	return r
}

func middleware(h http.Handler) http.Handler {
	// Allows to prevents CSRF and Double Submits
	cs := csrf.New(h, session.Store, session.Name)
	cs.FailureHandler(http.HandlerFunc(controller.InvalidToken))
	cs.ClearAfterUsage(true)
	cs.ExcludeRegexPaths([]string{"/static(.*)"})
	csrf.TokenLength = 32
	csrf.TokenName = "token"
	csrf.SingleToken = false
	h = cs

	// Log every request
	h = log.Handler(h)

	// Clear handler for Gorilla Context
	h = context.ClearHandler(h)

	return h
}
