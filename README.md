Данный проект демонстрирует реализацию защищённого протокола обмена сообщениями на языке C с использованием библиотеки OpenSSL.

## Структура проекта
```
Tayni_shifrov/
|-- cipher.h     — хедер с объявлением функций
|-- cipher.c     — реализация функций
|-- main.c       — симуляция работы программы
```

## Требования для работы

* gcc
* библиотека OpenSSL

## Клонирование репозитория
```
git clone https://github.com/FallenDriver/Tayni_shifrov
cd Tayni_shifrov
```

## Компиляция
```
gcc main.c cipher.c -o project -lssl -lcrypto
```

## Запуск
```
./project
```

