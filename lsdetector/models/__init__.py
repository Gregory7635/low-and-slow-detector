"""ML-модели: фабрика и обёртка AnomalyDetector (масштабирование + порог)."""

import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler

from .autoencoder import AutoencoderModel
from .base import AnomalyModel
from .iforest import IsolationForestModel

MODEL_REGISTRY = {m.name: m for m in (IsolationForestModel, AutoencoderModel)}


def create_model(name, **params) -> AnomalyModel:
    """Фабрика моделей по имени: 'iforest' или 'autoencoder'."""
    try:
        return MODEL_REGISTRY[name](**params)
    except KeyError:
        raise ValueError(f"неизвестная модель {name!r}, доступны: {sorted(MODEL_REGISTRY)}")


class AnomalyDetector:
    """Модель вместе со StandardScaler, порогом и списком признаков.

    Порог хранится вместе с моделью, чтобы predict на новых данных давал
    тот же результат, что и при оценке качества.
    """

    def __init__(self, model: AnomalyModel, feature_names):
        self.model = model
        self.feature_names = list(feature_names)
        self.scaler = StandardScaler()
        self.threshold = None
        self.meta = {}

    @property
    def name(self):
        return self.model.name

    def _transform(self, df):
        X = self.scaler.transform(df[self.feature_names].to_numpy(dtype=float))
        # отсечение выбросов, чтобы одно экстремальное значение не ломало сеть
        return np.clip(X, -8, 8)

    def fit(self, df_train, df_val=None):
        self.scaler.fit(df_train[self.feature_names].to_numpy(dtype=float))
        X_val = self._transform(df_val) if df_val is not None else None
        self.model.fit(self._transform(df_train), X_val)
        return self

    def score(self, df):
        return self.model.score(self._transform(df))

    def set_threshold_quantile(self, df_normal, q=0.98):
        """Порог по квантилю оценок обычных IP (когда разметки нет)."""
        self.threshold = float(np.quantile(self.score(df_normal), q))
        return self.threshold

    def predict(self, df):
        if self.threshold is None:
            raise RuntimeError("порог не задан: вызовите tune_threshold или set_threshold_quantile")
        return self.score(df) > self.threshold

    def explain(self, df, top=3):
        """Для каждой строки - top признаков с наибольшим вкладом в оценку."""
        contrib = self.model.feature_contributions(self._transform(df))
        order = np.argsort(-contrib, axis=1)[:, :top]
        return [[self.feature_names[j] for j in row] for row in order]

    def save(self, path):
        joblib.dump({"model_name": self.model.name, "model_state": self.model.get_state(),
                     "feature_names": self.feature_names, "scaler": self.scaler,
                     "threshold": self.threshold, "meta": self.meta}, path)

    @classmethod
    def load(cls, path):
        d = joblib.load(path)
        model = MODEL_REGISTRY[d["model_name"]].from_state(d["model_state"])
        obj = cls(model, d["feature_names"])
        obj.scaler, obj.threshold, obj.meta = d["scaler"], d["threshold"], d["meta"]
        return obj


__all__ = ["AnomalyDetector", "AnomalyModel", "AutoencoderModel", "IsolationForestModel",
           "MODEL_REGISTRY", "create_model"]
