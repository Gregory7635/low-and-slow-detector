"""Общий интерфейс моделей поиска аномалий."""

from abc import ABC, abstractmethod

import numpy as np


class AnomalyModel(ABC):
    """Модель обучается на «нормальных» IP и оценивает аномальность.

    Чем больше score, тем более необычно поведение IP. Признаки на вход
    подаются уже стандартизированными (это делает AnomalyDetector).
    """

    name: str

    @abstractmethod
    def fit(self, X: np.ndarray, X_val: np.ndarray | None = None) -> "AnomalyModel":
        ...

    @abstractmethod
    def score(self, X: np.ndarray) -> np.ndarray:
        ...

    def feature_contributions(self, X: np.ndarray) -> np.ndarray:
        """Вклад каждого признака в оценку (для объяснения результата).

        По умолчанию - модуль стандартизированного значения: насколько
        признак отклоняется от среднего по обучающей выборке.
        """
        return np.abs(X)

    @abstractmethod
    def get_state(self) -> dict:
        """Всё, что нужно для восстановления модели (сериализуется joblib)."""

    @classmethod
    @abstractmethod
    def from_state(cls, state: dict) -> "AnomalyModel":
        ...
