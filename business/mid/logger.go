package mid

import (
	"context"
	"log"
	"net/http"

	"github.com/ardanlabs/service/foundation/web"
)

// Logger ...
func Logger(log *log.Logger) web.Middleware {
	m := func(handler web.Handler) web.Handler {
		h := func(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
			err := handler(ctx, w, r)

			log.Println(r)

			return err
		}

		return h
	}

	return m
}
