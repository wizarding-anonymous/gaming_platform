// File: backend/services/account-service/internal/infrastructure/client/s3/s3_client.go
// account-service/internal/infrastructure/client/s3/s3_client.go
package s3

import (
"bytes"
"context"
"fmt"
"io"
"net/http"
"path/filepath"
"time"

"github.com/aws/aws-sdk-go/aws"
"github.com/aws/aws-sdk-go/aws/credentials"
"github.com/aws/aws-sdk-go/aws/session"
"github.com/aws/aws-sdk-go/service/s3"
"github.com/aws/aws-sdk-go/service/s3/s3manager"
"github.com/google/uuid"
)

// S3ClientImpl реализация клиента для работы с S3
type S3ClientImpl struct {
s3Client     *s3.S3
uploader     *s3manager.Uploader
downloader   *s3manager.Downloader
bucket       string
baseURL      string
presignedTTL time.Duration
}

// NewS3Client создает новый экземпляр клиента S3
func NewS3Client(endpoint, region, accessKey, secretKey, bucket, baseURL string, presignedTTL time.Duration) (*S3ClientImpl, error) {
sess, err := session.NewSession(&aws.Config{
Endpoint:         aws.String(endpoint),
Region:           aws.String(region),
Credentials:      credentials.NewStaticCredentials(accessKey, secretKey, ""),
S3ForcePathStyle: aws.Bool(true),
})
if err != nil {
return nil, fmt.Errorf("failed to create S3 session: %w", err)
}

s3Client := s3.New(sess)
uploader := s3manager.NewUploader(sess)
downloader := s3manager.NewDownloader(sess)

return &S3ClientImpl{
s3Client:     s3Client,
uploader:     uploader,
downloader:   downloader,
bucket:       bucket,
baseURL:      baseURL,
presignedTTL: presignedTTL,
}, nil
}

// UploadAvatar загружает аватар в S3
func (c *S3ClientImpl) UploadAvatar(ctx context.Context, accountID uuid.UUID, avatarType string, data []byte, contentType string) (string, string, error) {
// Генерация уникального имени файла
filename := fmt.Sprintf("%s/%s/%s%s", accountID.String(), avatarType, uuid.New().String(), filepath.Ext(contentType))

// Загрузка файла в S3
_, err := c.uploader.UploadWithContext(ctx, &s3manager.UploadInput{
Bucket:      aws.String(c.bucket),
Key:         aws.String(filename),
Body:        bytes.NewReader(data),
ContentType: aws.String(contentType),
})
if err != nil {
return "", "", fmt.Errorf("failed to upload avatar: %w", err)
}

// Формирование URL
url := fmt.Sprintf("%s/%s", c.baseURL, filename)

return url, filename, nil
}

// DeleteAvatar удаляет аватар из S3
func (c *S3ClientImpl) DeleteAvatar(ctx context.Context, filename string) error {
_, err := c.s3Client.DeleteObjectWithContext(ctx, &s3.DeleteObjectInput{
Bucket: aws.String(c.bucket),
Key:    aws.String(filename),
})
if err != nil {
return fmt.Errorf("failed to delete avatar: %w", err)
}

return nil
}

// GetPresignedURL получает предподписанный URL для загрузки файла
func (c *S3ClientImpl) GetPresignedURL(ctx context.Context, accountID uuid.UUID, avatarType string, contentType string) (string, string, error) {
// Генерация уникального имени файла
filename := fmt.Sprintf("%s/%s/%s%s", accountID.String(), avatarType, uuid.New().String(), filepath.Ext(contentType))

// Создание запроса на получение предподписанного URL
req, _ := c.s3Client.PutObjectRequest(&s3.PutObjectInput{
Bucket:      aws.String(c.bucket),
Key:         aws.String(filename),
ContentType: aws.String(contentType),
})

// Получение предподписанного URL
url, err := req.Presign(c.presignedTTL)
if err != nil {
return "", "", fmt.Errorf("failed to generate presigned URL: %w", err)
}

// Формирование URL для доступа к файлу после загрузки
fileURL := fmt.Sprintf("%s/%s", c.baseURL, filename)

return url, fileURL, nil
}

// DownloadAvatar скачивает аватар из S3
func (c *S3ClientImpl) DownloadAvatar(ctx context.Context, filename string) ([]byte, string, error) {
// Создание буфера для скачивания файла
buf := aws.NewWriteAtBuffer([]byte{})

// Скачивание файла из S3
_, err := c.downloader.DownloadWithContext(ctx, buf, &s3.GetObjectInput{
Bucket: aws.String(c.bucket),
Key:    aws.String(filename),
})
if err != nil {
return nil, "", fmt.Errorf("failed to download avatar: %w", err)
}

// Получение информации о файле
resp, err := c.s3Client.HeadObjectWithContext(ctx, &s3.HeadObjectInput{
Bucket: aws.String(c.bucket),
Key:    aws.String(filename),
})
if err != nil {
return nil, "", fmt.Errorf("failed to get avatar metadata: %w", err)
}

contentType := aws.StringValue(resp.ContentType)
if contentType == "" {
contentType = http.DetectContentType(buf.Bytes())
}

return buf.Bytes(), contentType, nil
}

// ListAvatars получает список аватаров пользователя
func (c *S3ClientImpl) ListAvatars(ctx context.Context, accountID uuid.UUID, avatarType string) ([]string, error) {
// Формирование префикса для поиска файлов
prefix := fmt.Sprintf("%s/%s/", accountID.String(), avatarType)

// Получение списка файлов из S3
resp, err := c.s3Client.ListObjectsV2WithContext(ctx, &s3.ListObjectsV2Input{
Bucket: aws.String(c.bucket),
Prefix: aws.String(prefix),
})
if err != nil {
return nil, fmt.Errorf("failed to list avatars: %w", err)
}

// Формирование списка URL
urls := make([]string, 0, len(resp.Contents))
for _, obj := range resp.Contents {
urls = append(urls, fmt.Sprintf("%s/%s", c.baseURL, aws.StringValue(obj.Key)))
}

return urls, nil
}

// GetObject получает объект из S3
func (c *S3ClientImpl) GetObject(ctx context.Context, key string) (io.ReadCloser, error) {
// Получение объекта из S3
resp, err := c.s3Client.GetObjectWithContext(ctx, &s3.GetObjectInput{
Bucket: aws.String(c.bucket),
Key:    aws.String(key),
})
if err != nil {
return nil, fmt.Errorf("failed to get object: %w", err)
}

return resp.Body, nil
}
