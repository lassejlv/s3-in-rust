// Compatibility test using the MinIO Go SDK, which uploads with signed aws-chunked payloads
// (STREAMING-AWS4-HMAC-SHA256-PAYLOAD) over plain HTTP.
//
//	S3RS_ENDPOINT=127.0.0.1:9000 S3RS_ACCESS_KEY=... S3RS_SECRET_KEY=... go run .
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

func must(err error, what string) {
	if err != nil {
		fmt.Printf("FAIL %s: %v\n", what, err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	ctx := context.Background()
	endpoint := env("S3RS_ENDPOINT", "127.0.0.1:9000")
	c, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(env("S3RS_ACCESS_KEY", "testkey"), env("S3RS_SECRET_KEY", "testsecret"), ""),
		Secure: false,
	})
	must(err, "client")
	_ = c.MakeBucket(ctx, "gotest", minio.MakeBucketOptions{})
	for _, size := range []int{0, 1, 100, 70000, 3 << 20, 17 << 20} {
		data := make([]byte, size)
		rand.Read(data)
		// size -1 forces streaming with unknown length (multipart for large); known size uses signed chunked streaming.
		for _, known := range []bool{true, false} {
			sz := int64(size)
			if !known {
				sz = -1
			}
			key := fmt.Sprintf("obj-%d-%v", size, known)
			_, err := c.PutObject(ctx, "gotest", key, bytes.NewReader(data), sz, minio.PutObjectOptions{ContentType: "application/x-go", PartSize: 5 << 20, UserMetadata: map[string]string{"k": "v"}})
			must(err, "put "+key)
			o, err := c.GetObject(ctx, "gotest", key, minio.GetObjectOptions{})
			must(err, "get "+key)
			got, err := io.ReadAll(o)
			must(err, "read "+key)
			if !bytes.Equal(got, data) {
				fmt.Printf("FAIL mismatch %s: %d vs %d\n", key, len(got), len(data))
				os.Exit(1)
			}
		}
	}
	n := 0
	for o := range c.ListObjects(ctx, "gotest", minio.ListObjectsOptions{Recursive: true}) {
		must(o.Err, "list")
		n++
	}
	fmt.Println("listed", n)
	_, err = c.CopyObject(ctx, minio.CopyDestOptions{Bucket: "gotest", Object: "copy"}, minio.CopySrcOptions{Bucket: "gotest", Object: "obj-70000-true"})
	must(err, "copy")
	st, err := c.StatObject(ctx, "gotest", "obj-100-true", minio.StatObjectOptions{})
	must(err, "stat")
	fmt.Println("stat", st.Size, st.ContentType, st.UserMetadata)
	for o := range c.ListObjects(ctx, "gotest", minio.ListObjectsOptions{Recursive: true}) {
		must(c.RemoveObject(ctx, "gotest", o.Key, minio.RemoveObjectOptions{}), "rm")
	}
	must(c.RemoveBucket(ctx, "gotest"), "rb")
	fmt.Println("MINIO-GO OK")
}
