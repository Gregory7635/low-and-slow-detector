"""Настраиваемые параметры детектора.

Всё, что пользователь может поменять из CLI или API, собрано в одном
dataclass. Справочные таблицы (версии браузеров, домены поисковиков)
лежат рядом с кодом, который их использует.
"""

from dataclasses import asdict, dataclass, field


@dataclass
class DetectorConfig:
    # Правило 2: сколько разных пар (браузер, ОС) на IP считать сигналом
    rule2_min_distinct: int = 2

    # Правило 5: запросы с разрывом <= burst_gap секунд - одна загрузка страницы
    rule5_burst_gap: float = 1.0
    rule5_min_visits: int = 5
    rule5_cv_threshold: float = 0.15

    # Правило 6: много IP одной подсети в скользящем окне
    subnet_prefix_v4: int = 24
    subnet_prefix_v6: int = 64
    subnet_ip_threshold: int = 5
    subnet_window: float = 600.0  # секунд; 0 - весь журнал целиком

    # Если правило 1 сработало, остальные не проверяются
    rule1_priority: bool = True
    # Считать IP без ответа DNS поддельными ботами
    dns_unknown_as_fake: bool = False
    # Не обращаться к DNS вообще (все заявленные боты получают статус unknown)
    dns_offline: bool = False

    # Признаки и модели
    min_requests: int = 5          # IP с меньшим числом запросов модель не оценивает
    random_state: int = 42

    whitelist: list = field(default_factory=list)  # CIDR-строки

    def to_dict(self):
        return asdict(self)
