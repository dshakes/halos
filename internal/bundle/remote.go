package bundle

import (
	"fmt"

	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// Repository opens a remote registry repository ("host/org/name") using
// docker-config credentials when available.
func Repository(repoRef string, plainHTTP bool) (*remote.Repository, error) {
	repo, err := remote.NewRepository(repoRef)
	if err != nil {
		return nil, fmt.Errorf("bundle: repository %q: %w", repoRef, err)
	}
	repo.PlainHTTP = plainHTTP
	c := &auth.Client{Client: retry.DefaultClient, Cache: auth.NewCache()}
	if store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{}); err == nil {
		c.Credential = credentials.Credential(store)
	}
	repo.Client = c
	return repo, nil
}
