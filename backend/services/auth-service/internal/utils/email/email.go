// File: backend/services/auth-service/internal/utils/email/email.go

package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"net/smtp"
	"time"

	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/config"
	"github.com/wizarding-anonymous/gaming_platform/backend/services/auth-service/internal/utils/logger"
)

// Client представляет клиент для отправки email
type Client struct {
	config *config.EmailConfig
	logger logger.Logger
}

// NewClient создает новый клиент для отправки email
func NewClient(config *config.EmailConfig, logger logger.Logger) *Client {
	return &Client{
		config: config,
		logger: logger,
	}
}

// SendEmail отправляет email
func (c *Client) SendEmail(ctx context.Context, to, subject, body string) error {
	// Проверяем контекст
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("context error: %w", err)
	}

	// Формируем заголовки email
	headers := make(map[string]string)
	headers["From"] = c.config.From
	headers["To"] = to
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=UTF-8"
	headers["Date"] = time.Now().Format(time.RFC1123Z)

	// Формируем сообщение
	var message bytes.Buffer
	for k, v := range headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}
	message.WriteString("\r\n")
	message.WriteString(body)

	// Настраиваем аутентификацию
	auth := smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.Host)

	// Настраиваем TLS
	tlsConfig := &tls.Config{
		ServerName:         c.config.Host,
		InsecureSkipVerify: false,
	}

	// Подключаемся к серверу
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", c.config.Host, c.config.Port), tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer conn.Close()

	// Создаем клиент SMTP
	client, err := smtp.NewClient(conn, c.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	// Аутентифицируемся
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	// Устанавливаем отправителя
	if err := client.Mail(c.config.From); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Устанавливаем получателя
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	// Отправляем сообщение
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	_, err = w.Write(message.Bytes())
	if err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	// Завершаем сессию
	err = client.Quit()
	if err != nil {
		return fmt.Errorf("failed to quit SMTP session: %w", err)
	}

	c.logger.Info("Email sent", "to", to, "subject", subject)
	return nil
}

// SendVerificationEmail отправляет email для подтверждения адреса электронной почты
func (c *Client) SendVerificationEmail(ctx context.Context, to, username, verificationLink string) error {
	subject := "Подтверждение адреса электронной почты"

	// Загружаем шаблон
	tmpl, err := template.New("verification").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Подтверждение адреса электронной почты</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .content {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
        }
        .button {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #777;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Подтверждение адреса электронной почты</h1>
    </div>
    <div class="content">
        <p>Здравствуйте, {{.Username}}!</p>
        <p>Благодарим вас за регистрацию в нашем сервисе. Для завершения регистрации необходимо подтвердить ваш адрес электронной почты.</p>
        <p>Пожалуйста, нажмите на кнопку ниже для подтверждения:</p>
        <p style="text-align: center;">
            <a href="{{.VerificationLink}}" class="button">Подтвердить email</a>
        </p>
        <p>Если вы не регистрировались в нашем сервисе, просто проигнорируйте это письмо.</p>
        <p>Ссылка действительна в течение 24 часов.</p>
    </div>
    <div class="footer">
        <p>Это автоматическое сообщение, пожалуйста, не отвечайте на него.</p>
        <p>&copy; {{.Year}} Российский аналог Steam. Все права защищены.</p>
    </div>
</body>
</html>
`)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Заполняем шаблон данными
	data := struct {
		Username         string
		VerificationLink string
		Year             int
	}{
		Username:         username,
		VerificationLink: verificationLink,
		Year:             time.Now().Year(),
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Отправляем email
	return c.SendEmail(ctx, to, subject, body.String())
}

// SendPasswordResetEmail отправляет email для сброса пароля
func (c *Client) SendPasswordResetEmail(ctx context.Context, to, username, resetLink string) error {
	subject := "Сброс пароля"

	// Загружаем шаблон
	tmpl, err := template.New("password_reset").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Сброс пароля</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .content {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
        }
        .button {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #777;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Сброс пароля</h1>
    </div>
    <div class="content">
        <p>Здравствуйте, {{.Username}}!</p>
        <p>Мы получили запрос на сброс пароля для вашего аккаунта. Если вы не запрашивали сброс пароля, просто проигнорируйте это письмо.</p>
        <p>Для сброса пароля, пожалуйста, нажмите на кнопку ниже:</p>
        <p style="text-align: center;">
            <a href="{{.ResetLink}}" class="button">Сбросить пароль</a>
        </p>
        <p>Ссылка действительна в течение 1 часа.</p>
    </div>
    <div class="footer">
        <p>Это автоматическое сообщение, пожалуйста, не отвечайте на него.</p>
        <p>&copy; {{.Year}} Российский аналог Steam. Все права защищены.</p>
    </div>
</body>
</html>
`)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Заполняем шаблон данными
	data := struct {
		Username  string
		ResetLink string
		Year      int
	}{
		Username:  username,
		ResetLink: resetLink,
		Year:      time.Now().Year(),
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Отправляем email
	return c.SendEmail(ctx, to, subject, body.String())
}

// SendWelcomeEmail отправляет приветственное письмо после регистрации
func (c *Client) SendWelcomeEmail(ctx context.Context, to, username string) error {
	subject := "Добро пожаловать в Российский аналог Steam"

	// Загружаем шаблон
	tmpl, err := template.New("welcome").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Добро пожаловать</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .content {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
        }
        .button {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #777;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Добро пожаловать в Российский аналог Steam</h1>
    </div>
    <div class="content">
        <p>Здравствуйте, {{.Username}}!</p>
        <p>Мы рады приветствовать вас в нашем сервисе. Ваша регистрация успешно завершена.</p>
        <p>Теперь вы можете:</p>
        <ul>
            <li>Покупать и скачивать игры</li>
            <li>Общаться с другими игроками</li>
            <li>Участвовать в сообществе</li>
            <li>Получать персональные рекомендации</li>
        </ul>
        <p style="text-align: center;">
            <a href="{{.LoginLink}}" class="button">Войти в аккаунт</a>
        </p>
    </div>
    <div class="footer">
        <p>Это автоматическое сообщение, пожалуйста, не отвечайте на него.</p>
        <p>&copy; {{.Year}} Российский аналог Steam. Все права защищены.</p>
    </div>
</body>
</html>
`)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Заполняем шаблон данными
	data := struct {
		Username  string
		LoginLink string
		Year      int
	}{
		Username:  username,
		LoginLink: c.config.BaseURL + "/login",
		Year:      time.Now().Year(),
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Отправляем email
	return c.SendEmail(ctx, to, subject, body.String())
}

// SendSecurityAlertEmail отправляет уведомление о подозрительной активности
func (c *Client) SendSecurityAlertEmail(ctx context.Context, to, username, alertType string, details map[string]string) error {
	var subject string
	var templateName string
	var templateContent string

	switch alertType {
	case "login":
		subject = "Уведомление безопасности: Новый вход в аккаунт"
		templateName = "security_login"
		templateContent = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Уведомление безопасности</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .content {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
        }
        .alert {
            background-color: #ffebee;
            border-left: 4px solid #f44336;
            padding: 10px;
            margin: 10px 0;
        }
        .button {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #777;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Уведомление безопасности</h1>
    </div>
    <div class="content">
        <p>Здравствуйте, {{.Username}}!</p>
        <div class="alert">
            <p>Мы обнаружили новый вход в ваш аккаунт:</p>
            <ul>
                <li><strong>Время:</strong> {{.Time}}</li>
                <li><strong>IP-адрес:</strong> {{.IP}}</li>
                <li><strong>Устройство:</strong> {{.Device}}</li>
                <li><strong>Местоположение:</strong> {{.Location}}</li>
            </ul>
        </div>
        <p>Если это были вы, то можете проигнорировать это сообщение.</p>
        <p>Если это были не вы, рекомендуем немедленно:</p>
        <ol>
            <li>Сменить пароль</li>
            <li>Включить двухфакторную аутентификацию</li>
            <li>Проверить историю входов в аккаунт</li>
        </ol>
        <p style="text-align: center;">
            <a href="{{.SecurityLink}}" class="button">Проверить безопасность аккаунта</a>
        </p>
    </div>
    <div class="footer">
        <p>Это автоматическое сообщение, пожалуйста, не отвечайте на него.</p>
        <p>&copy; {{.Year}} Российский аналог Steam. Все права защищены.</p>
    </div>
</body>
</html>
`
	case "password_changed":
		subject = "Уведомление безопасности: Пароль изменен"
		templateName = "security_password"
		templateContent = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Уведомление безопасности</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .content {
            background-color: #f9f9f9;
            padding: 20px;
            border-radius: 5px;
        }
        .alert {
            background-color: #ffebee;
            border-left: 4px solid #f44336;
            padding: 10px;
            margin: 10px 0;
        }
        .button {
            display: inline-block;
            background-color: #4CAF50;
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .footer {
            margin-top: 20px;
            font-size: 12px;
            color: #777;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Уведомление безопасности</h1>
    </div>
    <div class="content">
        <p>Здравствуйте, {{.Username}}!</p>
        <div class="alert">
            <p>Пароль от вашего аккаунта был изменен:</p>
            <ul>
                <li><strong>Время:</strong> {{.Time}}</li>
                <li><strong>IP-адрес:</strong> {{.IP}}</li>
            </ul>
        </div>
        <p>Если это были вы, то можете проигнорировать это сообщение.</p>
        <p>Если это были не вы, рекомендуем немедленно:</p>
        <ol>
            <li>Восстановить доступ к аккаунту через сброс пароля</li>
            <li>Связаться со службой поддержки</li>
        </ol>
        <p style="text-align: center;">
            <a href="{{.SecurityLink}}" class="button">Восстановить доступ</a>
        </p>
    </div>
    <div class="footer">
        <p>Это автоматическое сообщение, пожалуйста, не отвечайте на него.</p>
        <p>&copy; {{.Year}} Российский аналог Steam. Все права защищены.</p>
    </div>
</body>
</html>
`
	default:
		return errors.New("unknown alert type")
	}

	// Загружаем шаблон
	tmpl, err := template.New(templateName).Parse(templateContent)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	// Заполняем шаблон данными
	data := map[string]string{
		"Username":     username,
		"SecurityLink": c.config.BaseURL + "/account/security",
		"Year":         fmt.Sprintf("%d", time.Now().Year()),
	}

	// Добавляем детали
	for k, v := range details {
		data[k] = v
	}

	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	// Отправляем email
	return c.SendEmail(ctx, to, subject, body.String())
}
