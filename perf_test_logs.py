import time
import statistics
import requests
import matplotlib.pyplot as plt

API_BASE = "http://127.0.0.1:8000"

def measure_logs(limit: int, min_prob: float | None = None, n_runs: int = 20) -> float:
    """
    Mesure le temps moyen de réponse de /api/logs
    pour un certain limit + min_prob.
    """
    times = []

    params = {"limit": limit}
    if min_prob is not None:
        params["min_prob"] = min_prob

    for _ in range(n_runs):
        t0 = time.perf_counter()
        r = requests.get(f"{API_BASE}/api/logs", params=params)
        t1 = time.perf_counter()

        if r.status_code != 200:
            print("Erreur API:", r.status_code, r.text)
            return None

        times.append(t1 - t0)

    avg = statistics.mean(times)
    print(f"limit={limit}, min_prob={min_prob}, temps moyen={avg*1000:.2f} ms")
    return avg


def main():
    # Assure-toi d'avoir déjà beaucoup de logs dans Mongo (via generate_logs.py)
    limits = [50, 100, 200, 500, 1000]  # tu peux adapter
    results = []

    for limit in limits:
        avg_time = measure_logs(limit=limit, min_prob=None, n_runs=20)
        results.append(avg_time)

    # Tracé simple : limit vs temps moyen
    plt.figure()
    plt.plot(limits, [t * 1000 for t in results], marker="o")
    plt.xlabel("Nombre de logs retournés (limit)")
    plt.ylabel("Temps moyen de réponse (ms)")
    plt.title("Performance de /api/logs en fonction du nombre de résultats")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("perf_logs.png")
    plt.show()


if __name__ == "__main__":
    main()
