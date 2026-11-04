"""Нейросетевой автоэнкодер (PyTorch) для поиска аномального поведения IP.

Сеть сжимает вектор признаков до узкого скрытого слоя и восстанавливает
его обратно. Обучается только на обычных посетителях, поэтому поведение
ботов восстанавливает хуже: ошибка восстановления (MSE) и есть оценка
аномальности. Ошибка по каждому признаку показывает, чем именно IP
отличается от нормы.
"""

import copy

import numpy as np
import torch
from torch import nn

from .base import AnomalyModel


class _AutoencoderNet(nn.Module):
    def __init__(self, n_features, hidden=(32, 16), latent=6, dropout=0.1):
        super().__init__()
        enc, prev = [], n_features
        for h in hidden:
            enc += [nn.Linear(prev, h), nn.ReLU(), nn.Dropout(dropout)]
            prev = h
        enc.append(nn.Linear(prev, latent))
        dec, prev = [], latent
        for h in reversed(hidden):
            dec += [nn.Linear(prev, h), nn.ReLU()]
            prev = h
        dec.append(nn.Linear(prev, n_features))
        self.encoder = nn.Sequential(*enc)
        self.decoder = nn.Sequential(*dec)

    def forward(self, x):
        return self.decoder(self.encoder(x))


class AutoencoderModel(AnomalyModel):
    name = "autoencoder"

    def __init__(self, hidden=(32, 16), latent=6, dropout=0.1, lr=1e-3,
                 weight_decay=1e-5, epochs=300, batch_size=128, patience=25,
                 random_state=42, device=None):
        self.params = dict(hidden=tuple(hidden), latent=latent, dropout=dropout, lr=lr,
                           weight_decay=weight_decay, epochs=epochs, batch_size=batch_size,
                           patience=patience, random_state=random_state)
        # Сеть маленькая, на CPU она обучается быстрее, чем с копированием на GPU
        self.device = torch.device(device or "cpu")
        self.net = None
        self.n_features = None
        self.history = {"train_loss": [], "val_loss": []}

    def _tensor(self, X):
        return torch.as_tensor(np.asarray(X, dtype=np.float32), device=self.device)

    def _build(self, n_features):
        p = self.params
        self.n_features = n_features
        self.net = _AutoencoderNet(n_features, p["hidden"], p["latent"],
                                   p["dropout"]).to(self.device)

    def fit(self, X, X_val=None):
        p = self.params
        torch.manual_seed(p["random_state"])
        rng = np.random.default_rng(p["random_state"])
        X = np.asarray(X, dtype=np.float32)
        if X_val is None:   # отложить 15 % обучающих данных для ранней остановки
            idx = rng.permutation(len(X))
            cut = max(1, int(0.15 * len(X)))
            X, X_val = X[idx[cut:]], X[idx[:cut]]
        self._build(X.shape[1])
        opt = torch.optim.Adam(self.net.parameters(), lr=p["lr"],
                               weight_decay=p["weight_decay"])
        loss_fn = nn.MSELoss()
        xt, xv = self._tensor(X), self._tensor(X_val)
        best, best_state, wait = float("inf"), None, 0
        for _ in range(p["epochs"]):
            self.net.train()
            perm = torch.randperm(len(xt))
            total = 0.0
            for i in range(0, len(xt), p["batch_size"]):
                batch = xt[perm[i:i + p["batch_size"]]]
                opt.zero_grad()
                loss = loss_fn(self.net(batch), batch)
                loss.backward()
                opt.step()
                total += loss.item() * len(batch)
            self.net.eval()
            with torch.no_grad():
                val = loss_fn(self.net(xv), xv).item()
            self.history["train_loss"].append(total / len(xt))
            self.history["val_loss"].append(val)
            if val < best - 1e-5:
                best, best_state, wait = val, copy.deepcopy(self.net.state_dict()), 0
            else:
                wait += 1
                if wait >= p["patience"]:
                    break
        self.net.load_state_dict(best_state)
        self.net.eval()
        return self

    def reconstruction_errors(self, X):
        """Квадрат ошибки восстановления по каждому признаку."""
        with torch.no_grad():
            x = self._tensor(X)
            return ((self.net(x) - x) ** 2).cpu().numpy()

    def score(self, X):
        return self.reconstruction_errors(X).mean(axis=1)

    def feature_contributions(self, X):
        return self.reconstruction_errors(X)

    def get_state(self):
        return {"params": self.params, "n_features": self.n_features,
                "state_dict": {k: v.cpu() for k, v in self.net.state_dict().items()},
                "history": self.history}

    @classmethod
    def from_state(cls, state):
        obj = cls(**state["params"])
        obj._build(state["n_features"])
        obj.net.load_state_dict(state["state_dict"])
        obj.net.eval()
        obj.history = state.get("history", obj.history)
        return obj
