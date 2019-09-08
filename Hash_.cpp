#include "windows.h"
#include "iostream"
#include "WinCryptEx.h"

#define GR3411LEN  64

using namespace std;

int main()
{
	setlocale(LC_ALL, "Russian");
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	DWORD cbHash = 0;
	BYTE rgbHash[GR3411LEN];
	CHAR rgbDigits[] = "0123456789ABCDEF";

	// Инициализация контекста криптопровайдера
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_GOST_2012_256, CRYPT_VERIFYCONTEXT))
	{
		cout << "Ошибка инициализации контекста криптопровайдера" << endl;
		return 1;
	}

	cout << "Cryptographic provider initialized" << endl;

	// Cоздание хеш-объекта
	if (!CryptCreateHash(hProv, CALG_GR3411_2012_256, 0, 0, &hHash))
	{
		CryptReleaseContext(hProv, 0);
		cout << "Ошибка создания хеш-объекта" << endl;
		return 1;
	}

	cout << "Hash created" << endl;

	// Входные данные для хеширования
	char string[] = "Hello crypto world";
	DWORD count = strlen(string);

	cout << "Get Input Data: " << string << endl;

	// Передача хешируемых данных хэш-объекту.
	if (!CryptHashData(hHash, (BYTE*)string, count, 0))
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		cout << "Ошибка передачи хешируемых данных хэш-объекту" << endl;
		return 1;
	}

	cout << "Hash data loaded\n";

	// Получение хеш-значения
	cbHash = GR3411LEN;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
	{
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		cout << "CryptGetHashParam failed" << endl;
	}

	// Вывод на экран полученного хеш-значения
	cout << "Hash value: ";
	for (int i = 0; i < cbHash; i++)
	{
		printf("%c%c ", rgbDigits[rgbHash[i] >> 4],
			rgbDigits[rgbHash[i] & 0xf]);
	}
	cout << "\n\n";

	// Освобождение памяти
	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return 0;
}