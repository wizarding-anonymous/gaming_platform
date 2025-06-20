<!-- File: backend/CONTRIBUTING.md -->
# Руководство по внесению вклада в проект

Спасибо за интерес к нашему проекту! Мы рады любому вкладу, будь то исправление ошибок, добавление новых функций или улучшение документации.

## Процесс разработки

1. Форкните репозиторий
2. Создайте ветку для вашей функциональности (`git checkout -b feature/amazing-feature`)
3. Внесите изменения
4. Убедитесь, что код проходит все тесты и линтеры (`make test && make lint`)
5. Закоммитьте изменения (`git commit -m 'Add some amazing feature'`)
6. Отправьте изменения в ваш форк (`git push origin feature/amazing-feature`)
7. Создайте Pull Request в основной репозиторий

## Стандарты кодирования

### Go

- Следуйте [Effective Go](https://golang.org/doc/effective_go.html) и [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Используйте `gofmt` для форматирования кода
- Документируйте все публичные функции и типы
- Пишите тесты для всех новых функций

### Коммиты

Используйте [Conventional Commits](https://www.conventionalcommits.org/) для сообщений коммитов:

```
<тип>(опционально область): <описание>

[опционально тело]

[опционально подвал]
```

Типы коммитов:
- `feat`: новая функциональность
- `fix`: исправление ошибки
- `docs`: изменения в документации
- `style`: форматирование, отсутствующие точки с запятой и т.д.
- `refactor`: рефакторинг кода
- `test`: добавление тестов
- `chore`: обновление задач сборки и т.д.

## Структура проекта

Проект организован как монорепозиторий с микросервисной архитектурой. Каждый микросервис находится в своей директории и должен следовать стандартной структуре.

## Создание нового микросервиса

При создании нового микросервиса следуйте существующей структуре:

```
service-name/
├── api/            # API определения (REST, gRPC)
├── cmd/            # Точки входа приложения
├── config/         # Конфигурационные файлы
├── deployments/    # Файлы для развертывания (Docker, K8s)
├── internal/       # Внутренний код сервиса
├── migrations/     # Миграции базы данных
└── README.md       # Документация сервиса
```

## Отчеты об ошибках

Если вы обнаружили ошибку, пожалуйста, создайте issue в GitHub с подробным описанием проблемы, шагами для воспроизведения и ожидаемым поведением.

## Предложения по улучшению

Если у вас есть идеи по улучшению проекта, создайте issue с тегом "enhancement" и подробно опишите ваше предложение.

## Вопросы

Если у вас возникли вопросы по проекту, создайте issue с тегом "question".
