<!-- File: backend/services/auth-service/CONTRIBUTING.md -->
# Руководство по внесению изменений

Данное руководство описывает процесс внесения изменений в микросервис Auth Service.

## Содержание

- [Процесс разработки](#процесс-разработки)
- [Ветвление](#ветвление)
- [Коммиты](#коммиты)
- [Pull Requests](#pull-requests)
- [Стиль кода](#стиль-кода)
- [Тестирование](#тестирование)
- [Документация](#документация)
- [CI/CD](#cicd)

## Процесс разработки

1. Создайте issue в репозитории с описанием задачи или бага
2. Создайте ветку от `main` для работы над задачей
3. Внесите необходимые изменения, следуя стандартам кодирования
4. Напишите тесты для новой функциональности
5. Обновите документацию
6. Создайте Pull Request в ветку `main`
7. Дождитесь прохождения CI/CD и ревью кода
8. После одобрения, выполните merge в `main`

## Ветвление

Используйте следующие префиксы для веток:

- `feature/` - для новых функций
- `bugfix/` - для исправления багов
- `hotfix/` - для срочных исправлений в продакшене
- `refactor/` - для рефакторинга кода
- `docs/` - для изменений в документации
- `test/` - для добавления или изменения тестов
- `chore/` - для обновления зависимостей, конфигураций и т.д.

Пример: `feature/telegram-login`

## Коммиты

Используйте [Conventional Commits](https://www.conventionalcommits.org/) для структурирования сообщений коммитов:

```
<тип>[опциональная область]: <описание>

[опциональное тело]

[опциональный футер]
```

Типы коммитов:
- `feat`: новая функциональность
- `fix`: исправление бага
- `docs`: изменения в документации
- `style`: форматирование, отсутствующие точки с запятой и т.д.
- `refactor`: рефакторинг кода
- `test`: добавление тестов
- `chore`: обновление зависимостей и т.д.

Примеры:
```
feat(auth): добавить интеграцию с Telegram Login
fix(token): исправить ошибку валидации refresh token
docs: обновить README.md
```

## Pull Requests

- Название PR должно кратко описывать изменения
- Описание PR должно содержать:
  - Ссылку на issue
  - Описание изменений
  - Инструкции по тестированию
  - Скриншоты (если применимо)
- PR должен быть связан с issue через ключевые слова (например, "Closes #123")
- PR должен пройти все проверки CI/CD
- PR должен получить одобрение минимум от одного ревьюера

## Стиль кода

### Go

- Следуйте [Effective Go](https://golang.org/doc/effective_go) и [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Используйте `gofmt` для форматирования кода
- Используйте `golint` и `go vet` для проверки кода
- Максимальная длина строки: 100 символов
- Используйте CamelCase для имен функций, переменных и типов
- Используйте комментарии для документирования публичных функций и типов

### SQL

- Используйте snake_case для имен таблиц и колонок
- Ключевые слова SQL должны быть в верхнем регистре
- Используйте отступы для улучшения читаемости запросов

## Тестирование

- Пишите модульные тесты для всех новых функций
- Пишите интеграционные тесты для взаимодействия компонентов
- Используйте таблично-управляемые тесты, где это возможно
- Тесты должны быть независимыми и не полагаться на порядок выполнения
- Используйте моки для внешних зависимостей
- Стремитесь к покрытию кода тестами не менее 80%

## Документация

- Обновляйте README.md при добавлении новых функций
- Документируйте все публичные API (REST и gRPC)
- Обновляйте Swagger-документацию при изменении REST API
- Обновляйте proto-файлы при изменении gRPC API
- Добавляйте комментарии к сложным алгоритмам и бизнес-логике

## CI/CD

Проект использует GitHub Actions для CI/CD. Каждый Pull Request проходит следующие проверки:

- Сборка проекта
- Линтинг кода
- Запуск модульных тестов
- Запуск интеграционных тестов
- Проверка покрытия кода тестами
- Сборка Docker-образа

После слияния в `main` происходит:

- Сборка и публикация Docker-образа
- Деплой в тестовую среду
- Запуск нагрузочных тестов
- Деплой в продакшен (после ручного подтверждения)

## Контакты

Если у вас возникли вопросы или предложения по улучшению процесса разработки, обращайтесь к команде разработки:

- Email: dev-team@gaiming.ru
- Slack: #auth-service-dev
