package mmrtesting

import (
	"context"
	"testing"

	"github.com/datatrails/go-datatrails-common/azblob"
	"github.com/datatrails/go-datatrails-common/logger"
	"github.com/stretchr/testify/require"
)

type TestContext struct {
	Log    logger.Logger
	Storer *azblob.Storer
	T      *testing.T
}

// XXX: TODO TenantMassifPrefix duplicated here to avoid import cycle. refactor
const (
	ValueBytes       = 32
	V1MMRPrefix      = "v1/mmrs"
	V1MMRBlobNameFmt = "%016d.log"
)

type TestConfig struct {
	// We seed the RNG of the provided StartTimeMS. It is normal to force it to
	// some fixed value so that the generated data is the same from run to run.
	StartTimeMS     int64
	EventRate       int
	TestLabelPrefix string
	TenantIdentity  string // can be ""
	Container       string // can be "" defaults to TestLablePrefix
}

func NewTestContext(t *testing.T, cfg TestConfig) TestContext {
	c := TestContext{
		T: t,
	}
	logger.New("INFO")
	c.Log = logger.Sugar.WithServiceName(cfg.TestLabelPrefix)

	container := cfg.Container
	if container == "" {
		container = cfg.TestLabelPrefix
	}

	var err error
	c.Storer, err = azblob.NewDev(azblob.NewDevConfigFromEnv(), container)
	if err != nil {
		t.Fatalf("failed to connect to blob store emulator: %v", err)
	}
	client := c.Storer.GetServiceClient()
	// Note: we expect a 'already exists' error here and  ignore it.
	_, _ = client.CreateContainer(context.Background(), container, nil)

	return c
}

func (c *TestContext) GetLog() logger.Logger { return c.Log }

func (c *TestContext) GetStorer() *azblob.Storer {
	return c.Storer
}

func (c *TestContext) DeleteBlobsByPrefix(blobPrefixPath string) {
	var err error
	var r *azblob.ListerResponse
	var blobs []string

	var marker azblob.ListMarker
	for {
		r, err = c.Storer.List(
			context.Background(),
			azblob.WithListPrefix(blobPrefixPath), azblob.WithListMarker(marker) /*, azblob.WithListTags()*/)

		require.NoError(c.T, err)

		for _, i := range r.Items {
			blobs = append(blobs, *i.Name)
		}
		if len(r.Items) == 0 || r.Marker == nil {
			break
		}
		marker = r.Marker
	}
	for _, blobPath := range blobs {
		err = c.Storer.Delete(context.Background(), blobPath)
		require.NoError(c.T, err)
	}
}
