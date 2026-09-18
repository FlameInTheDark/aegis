package platform

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/FlameInTheDark/aegis/internal/observability"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ObjectStore is an S3-compatible object storage client used for raw
// evidence, report artifacts, scanner output and feed snapshots.
type ObjectStore struct {
	cli    *minio.Client
	bucket string
}

// NewObjectStore connects to any S3-compatible endpoint (RustFS by default;
// works with MinIO, AWS S3 and friends as well).
func NewObjectStore(ctx context.Context, endpoint, accessKey, secretKey, bucket string, useSSL bool) (*ObjectStore, error) {
	cli, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
		Region: "",
	})
	if err != nil {
		return nil, fmt.Errorf("s3: client: %w", err)
	}
	s := &ObjectStore{cli: cli, bucket: bucket}
	if err := s.ensureBucket(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *ObjectStore) ensureBucket(ctx context.Context) error {
	ok, err := s.cli.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("s3: bucket probe: %w", err)
	}
	if !ok {
		if err := s.cli.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("s3: create bucket: %w", err)
		}
	}
	return nil
}

// Put uploads bytes under a key with a content type.
func (s *ObjectStore) Put(ctx context.Context, key string, data []byte, contentType string) error {
	_, err := s.cli.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType})
	return err
}

// PutStream uploads from a reader.
func (s *ObjectStore) PutStream(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	_, err := s.cli.PutObject(ctx, s.bucket, key, r, size, minio.PutObjectOptions{ContentType: contentType})
	return err
}

// Get downloads an object.
func (s *ObjectStore) Get(ctx context.Context, key string) ([]byte, error) {
	obj, err := s.cli.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	return io.ReadAll(obj)
}

// PresignedGet returns a short-lived download URL for secure artifact access.
func (s *ObjectStore) PresignedGet(ctx context.Context, key string, ttl time.Duration) (string, error) {
	u, err := s.cli.PresignedGetObject(ctx, s.bucket, key, ttl, nil)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// Stat returns object metadata.
func (s *ObjectStore) Stat(ctx context.Context, key string) (int64, error) {
	info, err := s.cli.StatObject(ctx, s.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		return 0, err
	}
	return info.Size, nil
}

// Delete removes an object (retention sweeps).
func (s *ObjectStore) Delete(ctx context.Context, key string) error {
	return s.cli.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{})
}

// Health implements observability.Checker.
func (s *ObjectStore) CheckHealth(ctx context.Context) observability.DependencyHealth {
	if s == nil {
		return observability.DependencyHealth{Name: "object_storage", Status: "down", Detail: "not configured"}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := s.cli.BucketExists(ctx, s.bucket); err != nil {
		return observability.DependencyHealth{Name: "object_storage", Status: "down", Detail: err.Error()}
	}
	return observability.DependencyHealth{Name: "object_storage", Status: "ok"}
}

var _ = http.MethodGet
