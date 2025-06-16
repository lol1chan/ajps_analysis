#include <gmpxx.h>
#include <random>
#include <iostream>

// Ймовірнісна перевірка простоти: тест Міллера–Рабіна
bool is_probable_prime(const mpz_class& n, int k = 100) {
    if (n < 2) return false;
    if (n == 2 || n == 3) return true;
    if (n % 2 == 0) return false;

    mpz_class d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        ++r;
    }

    gmp_randclass rng(gmp_randinit_default);
    rng.seed(static_cast<unsigned long>(std::random_device{}()));

    for (int i = 0; i < k; ++i) {
        mpz_class a = rng.get_z_range(n - 3) + 2;

        mpz_class x;
        mpz_powm(x.get_mpz_t(), a.get_mpz_t(), d.get_mpz_t(), n.get_mpz_t());
        if (x == 1 || x == n - 1)
            continue;
        bool next = false;
        for (int j = 0; j < r - 1; ++j) {
            mpz_powm_ui(x.get_mpz_t(), x.get_mpz_t(), 2, n.get_mpz_t());
            if (x == n - 1) {
                next = true;
                break;
            }
        }
        if (!next)
            return false;
    }
    return true;
}


mpz_class mersenne_number(unsigned int n) {
    mpz_class res = 1;
    mpz_mul_2exp(res.get_mpz_t(), res.get_mpz_t(), n);
    res -= 1;
    return res;
}

// Пошук найменшого c: число Кренделла
bool find_smallest_crandall(unsigned int n, mpz_class& c_out, mpz_class& candidate_out, unsigned int max_c = 2^(n-1/2)) {
    mpz_class base = 1;
    mpz_mul_2exp(base.get_mpz_t(), base.get_mpz_t(), n);
    for (mpz_class c = 0; c < max_c; с+=2) {
        mpz_class candidate = base - c;
        if (candidate > 1 && is_probable_prime(candidate)) {
            c_out = c;
            candidate_out = candidate;
            return true;
        }
    }
    return false;
}

// Пошук найменшого m: узагальнене число Мерсенна
bool find_smallest_generalized_mersenne(unsigned int n, mpz_class& m_out, mpz_class& candidate_out) {
    mpz_class base = 1;
    mpz_mul_2exp(base.get_mpz_t(), base.get_mpz_t(), n);
    for (mpz_class m = 1; m < n; m++) {
        mpz_class power_m = 1;
        mpz_mul_2exp(power_m.get_mpz_t(), power_m.get_mpz_t(), m.get_ui());
        mpz_class candidate = base - power_m - 1;
        if (candidate > 1 && is_probable_prime(candidate)) {
            m_out = m;
            candidate_out = candidate;
            return true;
        }
    }
    return false;
}

void analyze_mersenne(unsigned int n) {
    mpz_class Mn = mersenne_number(n);
    std::cout << "Перевірка числа Мерсенна Mn = 2^" << n << " - 1" << std::endl;

    if (is_probable_prime(Mn)) {
        std::cout << "Mn є простим числом!" << std::endl;

        mpz_class c, crandall;
        if (find_smallest_crandall(n, c, crandall)) {
            std::cout << "Найменше c > 1, таке що 2^" << n << " - c — просте (число Кренделла):" << std::endl;
            std::cout << "    c = " << c << std::endl;
        } else {
            std::cout << "Не знайдено підходящого c для числа Кренделла." << std::endl;
        }

        mpz_class m, generalized;
        if (find_smallest_generalized_mersenne(n, m, generalized)) {
            std::cout << "Найменше m < n, таке що 2^" << n << " - 2^m - 1 — просте (узагальнене число Мерсенна):" << std::endl;
            std::cout << "    m = " << m << std::endl;
        } else {
            std::cout << "Не знайдено підходящого m для узагальненого числа Мерсенна." << std::endl;
        }
    } else {
        std::cout << "Mn не є простим числом." << std::endl;
    }
}

int main() {
    std::cout << "Початок виконання!\n";
    unsigned int n = 11213; 
    analyze_mersenne(n);

    return 0;
}
