"""One-Class SVM и Local Outlier Factor - альтернативы, с которыми
сравниваются основные модели (см. docs/04_testing.md, раздел 4.2)."""

from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM

from .base import AnomalyModel


class OneClassSVMModel(AnomalyModel):
    name = "ocsvm"

    def __init__(self, nu=0.05, gamma="scale", kernel="rbf", random_state=None):
        # random_state не используется: OneClassSVM детерминирован
        self.params = dict(nu=nu, gamma=gamma, kernel=kernel)
        self.model = OneClassSVM(**self.params)

    def fit(self, X, X_val=None):
        self.model.fit(X)
        return self

    def score(self, X):
        return -self.model.decision_function(X)

    def get_state(self):
        return {"params": self.params, "model": self.model}

    @classmethod
    def from_state(cls, state):
        obj = cls(**state["params"])
        obj.model = state["model"]
        return obj


class LocalOutlierFactorModel(AnomalyModel):
    name = "lof"

    def __init__(self, n_neighbors=20, random_state=None):
        self.params = dict(n_neighbors=n_neighbors)
        # novelty=True - режим оценки новых данных после обучения
        self.model = LocalOutlierFactor(n_neighbors=n_neighbors, novelty=True)

    def fit(self, X, X_val=None):
        self.model.fit(X)
        return self

    def score(self, X):
        return -self.model.score_samples(X)

    def get_state(self):
        return {"params": self.params, "model": self.model}

    @classmethod
    def from_state(cls, state):
        obj = cls(**state["params"])
        obj.model = state["model"]
        return obj
