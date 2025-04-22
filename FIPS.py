import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import random

class FIPS186Generator:
    def __init__(self, b, t=None):
        """
        Инициализация генератора FIPS-186
        b: размер в битах (160 ≤ b ≤ 512)
        t: вспомогательное слово (в шестнадцатеричном формате)
        """
        if not 160 <= b <= 512:
            raise ValueError("b должно быть от 160 до 512")
        self.b = b
        # Шаг 1: Задать произвольное число b: 160 ≤ b ≤ 512
        self.q = (1 << b) - 1
        # Шаг 2: Сгенерировать случайное b-битное начальное значение z
        self.z = random.getrandbits(b)
        # Шаг 3: Задать вспомогательное 160-битное слово t
        if t is None:
            t = "67452301efcdab8998badcfe10325476c3d2e1f0"
        # Проверяем, что t является корректным 160-битным словом (40 символов в hex)
        if len(t.replace(" ", "")) != 40:
            raise ValueError("t должно быть 160-битным словом (40 символов в hex)")
        try:
            self.t = bytes.fromhex(t.replace(" ", ""))
        except ValueError:
            raise ValueError("Некорректный формат шестнадцатеричного числа")

    def G(self, c):
        """
        Алгоритм вычисления значений функции G(t,c):
        1. Разбить слово t на пять 32-битных слов
        2. К слову c дописать справа 512-b нулей
        3. Разбить слово M на шестнадцать 32-битных слов
        4. Выполнить 1 раз шаг 4 алгоритма SHA-1
        5. Выходное слово является конкатенацией H0||H1||H2||H3||H4
        """
        # Шаг 1: Разбиваем t на пять 32-битных слов
        H0 = 0x67452301
        H1 = 0xEFCDAB89
        H2 = 0x98BADCFE
        H3 = 0x10325476
        H4 = 0xC3D2E1F0

        # Шаг 2: Дополняем c до 512 бит
        M = c + b'\x00' * (64 - len(c))  # 512 бит = 64 байта

        # Шаг 3: Разбиваем M на 16 32-битных слов
        W = []
        for i in range(0, 64, 4):
            W.append(int.from_bytes(M[i:i+4], 'big'))

        # Шаг 4: Выполняем один раунд SHA-1
        A, B, C, D, E = H0, H1, H2, H3, H4

        for i in range(16):
            if i < 16:
                f = (B & C) | ((~B) & D)
                k = 0x5A827999
            temp = ((A << 5) | (A >> 27)) + f + E + k + W[i]
            E = D
            D = C
            C = ((B << 30) | (B >> 2))
            B = A
            A = temp & 0xFFFFFFFF

        # Шаг 5: Формируем выходное значение как конкатенацию
        H0 = (H0 + A) & 0xFFFFFFFF
        H1 = (H1 + B) & 0xFFFFFFFF
        H2 = (H2 + C) & 0xFFFFFFFF
        H3 = (H3 + D) & 0xFFFFFFFF
        H4 = (H4 + E) & 0xFFFFFFFF

        return H0.to_bytes(4, 'big') + H1.to_bytes(4, 'big') + \
               H2.to_bytes(4, 'big') + H3.to_bytes(4, 'big') + \
               H4.to_bytes(4, 'big')

    def generate_sequence(self, count):
        """
        Генерация последовательности псевдослучайных чисел
        count: количество генерируемых бит
        """
        result_bits = ""
        x = 0
        
        while len(result_bits) < count:
            # Шаг 4.1: положить yi равным нулю
            y = 0
            
            # Шаг 4.2: вычислить zi = (z + yi) mod 2^b
            z = (self.z + y) % self.q
            
            # Шаг 4.3: вычислить c = G(t,z)
            z_bytes = z.to_bytes((self.b + 7) // 8, 'big')
            c = self.G(z_bytes)
            
            # Шаг 4.4: вычислить z = (1 + z + x) mod 2^b
            self.z = (1 + z + x) % self.q
            
            # Преобразуем результат в биты
            value = int.from_bytes(c, 'big')
            bits = bin(value)[2:].zfill(160)  # SHA-1 дает 160 бит
            result_bits += bits
            
            # Обновляем x для следующей итерации
            x = value
        
        # Возвращаем только запрошенное количество бит
        return result_bits[:count]

def frequency_test(bits):
    """
    Частотный тест:
    1. Преобразование последовательности 0 и 1 в -1 и 1
    2. Вычисление суммы Sn
    3. Вычисление статистики S
    4. Проверка условия S ≤ 1.82138636
    """
    # Шаг 1: Преобразование в последовательность -1 и 1
    x = [1 if b == "1" else -1 for b in bits]
    n = len(bits)
    
    # Шаг 2: Вычисление суммы Sn
    Sn = sum(x)
    
    # Шаг 3: Вычисление статистики S
    S = abs(Sn) / (n ** 0.5)
    
    # Шаг 4: Проверка условия
    passed = S <= 1.82138636
    
    result = f"""Частотный тест:
Длина последовательности: {n}
Сумма (Sn): {Sn}
Статистика (S): {S:.8f}
Пороговое значение: 1.82138636
Результат: {"Пройден" if passed else "Провален"}"""
    return result

def runs_test(bits):
    """
    Тест на последовательность одинаковых бит:
    1. Вычисление частоты π единиц
    2. Вычисление значения τ
    3. Вычисление статистики S
    4. Проверка условия S ≤ 1.82138636
    """
    n = len(bits)
    
    # Шаг 1: Вычисление частоты π
    ones = bits.count("1")
    pi = ones / n

    # Шаг 2: Вычисление τ и r(k)
    v = 1  # начальное значение для подсчета серий
    for i in range(1, n):
        if bits[i] != bits[i-1]:
            v += 1
    
    # Шаг 3: Вычисление статистики S
    S = abs(v - 2 * n * pi * (1 - pi)) / (2 * (n * pi * (1 - pi)) ** 0.5)
    
    # Шаг 4: Проверка условия
    passed = S <= 1.82138636
    
    result = f"""Тест на последовательность одинаковых бит:
Длина последовательности: {n}
Частота единиц (π): {pi:.8f}
Количество серий (v): {v}
Ожидаемое количество серий: {2 * n * pi * (1 - pi):.2f}
Статистика (S): {S:.8f}
Пороговое значение: 1.82138636
Результат: {"Пройден" if passed else "Провален"}"""
    return result

def cumulative_sums_test_extended(bits):
    # Шаг 1: Преобразование последовательности
    k = len(bits)
    x = [1 if b == '1' else -1 for b in bits]
    
    # Шаг 2: Вычисление сумм Si
    S = []
    current_sum = 0
    for xi in x:
        current_sum += xi
        S.append(current_sum)
    
    # Шаг 3: Формирование S' = Si - i/2
    S_prime = [s - (i + 1)/2 for i, s in enumerate(S)]

    # Шаг 4: Вычисление L = k - 1
    L = k - 1
    
    # Шаг 5: Подсчет ξj для 18 состояний
    states = list(range(-9, 10))  # от -9 до 9
    xi = {j: 0 for j in states}
    for s in S_prime:
        for j in states:
            if abs(s - j) < 0.5:  # Проверка на попадание в состояние j
                xi[j] += 1
    
    # Шаг 6: Вычисление статистик Vj
    passed = True
    result = "Тест на произвольные отклонения:\n"
    result += f"Длина последовательности: {k}\n"
    result += "Статистики для каждого состояния:\n"
    
    for j in states:
        # Вычисление статистики по формуле из документа
        v = abs(xi[j] - k/(L+1)) / ((k * (L-1)/(L+1)) ** 0.5)
        
        result += f"Состояние {j: >3}: посещений = {xi[j]: >5}, "
        result += f"статистика V{j} = {v:.8f}"
        
        # Шаг 7: Проверка условия Vj ≤ 1.82138636
        if v > 1.82138636:
            result += " *\n"
            passed = False
        else:
            result += "\n"

    result += f"\nПороговое значение: 1.82138636\n"
    result += f"Результат: {'Пройден' if passed else 'Провален'}"
    return result

class App(tk.Tk):
    def __init__(self):
        super().__init__()

        self.geometry("800x600")

        # Создание и размещение элементов интерфейса
        tk.Label(self, text="Размер b (160-512):").pack(pady=5)
        self.b_entry = tk.Entry(self)
        self.b_entry.pack(pady=5)
        self.b_entry.insert(0, "160")

        tk.Label(self, text="Вспомогательное слово t (hex):").pack(pady=5)
        self.t_entry = tk.Entry(self, width=50)
        self.t_entry.pack(pady=5)
        self.t_entry.insert(0, "67452301 efcdab89 98badcfe 10325476 c3d2e1f0")

        tk.Label(self, text="Количество генерируемых бит:").pack(pady=5)
        self.count_entry = tk.Entry(self)
        self.count_entry.pack(pady=5)
        self.count_entry.insert(0, "1000")

        # Кнопки
        tk.Button(self, text="Генерировать", command=self.generate).pack(pady=10)
        tk.Button(self, text="Запустить тесты", command=self.run_tests).pack(pady=5)
        tk.Button(self, text="Сохранить в файл", command=self.save_to_file).pack(pady=5)

        # Текстовое поле для вывода результатов
        self.result_text = tk.Text(self, height=20, width=80)
        self.result_text.pack(pady=10)

    def generate(self):
        try:
            b = int(self.b_entry.get())
            count = int(self.count_entry.get())
            t = self.t_entry.get()

            # Создание генератора
            generator = FIPS186Generator(b, t)
            
            # Генерация последовательности
            sequence = generator.generate_sequence(count)
            
            # Вывод результатов
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Сгенерированная последовательность ({len(sequence)} бит):\n")
            self.result_text.insert(tk.END, sequence)
            
            # Сохраняем последовательность для тестов
            self.last_sequence = sequence
            
        except ValueError as e:
            messagebox.showerror("Ошибка", str(e))
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")

    def run_tests(self):
        if not self.last_sequence:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте последовательность.")
            return
        self.result_text.delete("1.0", tk.END)
        self.result_text.insert(tk.END, frequency_test(self.last_sequence) + "\n\n")
        self.result_text.insert(tk.END, runs_test(self.last_sequence) + "\n\n")
        self.result_text.insert(tk.END, cumulative_sums_test_extended(self.last_sequence))

    def save_to_file(self):
        if not self.last_sequence:
            messagebox.showerror("Ошибка", "Нет данных для сохранения.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w") as f:
                f.write(self.last_sequence)

if __name__ == "__main__":
    app = App()
    app.mainloop()
