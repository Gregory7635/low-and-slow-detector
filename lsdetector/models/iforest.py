"""Isolation Forest - базовый (не нейросетевой) метод поиска аномалий."""

from sklearn.ensemble import IsolationForest

from .base import AnomalyModel


class IsolationForestModel(AnomalyModel):
    name = "iforest"

    def __init__(self, n_estimators=300, max_samples="auto", contamination="auto",
                 random_state=42):
        self.params = dict(n_estimators=n_estimators, max_samples=max_samples,
                           contamination=contamination, random_state=random_state)
        self.model = IsolationForest(n_jobs=-1, **self.params)

    def fit(self, X, X_val=None):
        self.model.fit(X)
        return self

    def score(self, X):
        # score_samples: чем меньше, тем аномальнее - меняем знак
        return -self.model.score_samples(X)

    def get_state(self):
        return {"params": self.params, "model": self.model}

    @classmethod
    def from_state(cls, state):
        obj = cls(**state["params"])
        obj.model = state["model"]
        return obj
