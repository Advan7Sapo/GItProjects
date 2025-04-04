#include <iostream>
#include <string>
#include <vector>
#include <stack>
#include <cctype>
#include <cstdlib>
#include <windows.h>

using namespace std;

// Função para configurar a codificação do console
void configurarConsole() {
    SetConsoleOutputCP(CP_UTF8);
}

// Função para limpar a tela
void limparTela() {
    system("cls");
}

// Função para verificar se é um número
bool isNumber(const string& str) {
    for (char c : str) {
        if (!isdigit(c) && c != '-' && c != '.') return false;
    }
    return true;
}

// Função para verificar precedência dos operadores
int getPrecedence(char op) {
    if (op == '*' || op == '/' || op == '%') return 2;
    if (op == '+' || op == '-') return 1;
    return 0;
}

// Função para tokenizar a equação
vector<string> tokenize(const string& equation) {
    vector<string> tokens;
    string currentToken;
    
    for (char c : equation) {
        if (isdigit(c) || c == '.' || (c == '-' && currentToken.empty())) {
            currentToken += c;
        } else if (c == '+' || c == '-' || c == '*' || c == '/' || c == '%') {
            if (!currentToken.empty()) {
                tokens.push_back(currentToken);
                currentToken.clear();
            }
            tokens.push_back(string(1, c));
        }
    }
    
    if (!currentToken.empty()) {
        tokens.push_back(currentToken);
    }
    
    return tokens;
}

// Função para converter infix para postfix
vector<string> infixToPostfix(const vector<string>& infix) {
    vector<string> postfix;
    stack<string> operators;
    
    for (const string& token : infix) {
        if (isNumber(token)) {
            postfix.push_back(token);
        } else {
            while (!operators.empty() && 
                   getPrecedence(operators.top()[0]) >= getPrecedence(token[0])) {
                postfix.push_back(operators.top());
                operators.pop();
            }
            operators.push(token);
        }
    }
    
    while (!operators.empty()) {
        postfix.push_back(operators.top());
        operators.pop();
    }
    
    return postfix;
}

// Função para avaliar expressão postfix
long long evaluatePostfix(const vector<string>& postfix) {
    stack<long long> values;
    
    for (const string& token : postfix) {
        if (isNumber(token)) {
            values.push(stoll(token));
        } else {
            long long val2 = values.top(); values.pop();
            long long val1 = values.top(); values.pop();
            
            switch (token[0]) {
                case '+': values.push(val1 + val2); break;
                case '-': values.push(val1 - val2); break;
                case '*': values.push(val1 * val2); break;
                case '/': 
                    if (val2 == 0) {
                        cout << "Erro: Divisão por zero!" << endl;
                        exit(1);
                    }
                    values.push(val1 / val2); 
                    break;
                case '%': 
                    if (val2 == 0) {
                        cout << "Erro: Módulo por zero!" << endl;
                        exit(1);
                    }
                    values.push(val1 % val2); 
                    break;
            }
        }
    }
    
    return values.top();
}

int main() {
    configurarConsole();
    limparTela();
    
    string equation;
    char c;
    bool primeiroNumero = true;

    cout << "=== Calculadora PontoG ===" << endl;
    cout << "Operadores disponíveis: +, -, *, /, %" << endl;
    cout << "Digite '=' para calcular" << endl << endl;

    while (true) {
        if (primeiroNumero) {
            cout << "Digite o primeiro número: ";
            primeiroNumero = false;
        } else {
            cout << "Digite um operador ou '=' para calcular: ";
        }

        cin >> c;
        
        if (c == '=') break;
        
        equation += c;
        
        if (c == '+' || c == '-' || c == '*' || c == '/' || c == '%') {
            cout << "Digite o próximo número: ";
            cin >> c;
            equation += c;
        }

        limparTela();
        cout << "=== Calculadora PontoG ===" << endl;
        cout << "Equação atual: " << equation << endl << endl;
    }

    vector<string> tokens = tokenize(equation);
    vector<string> postfix = infixToPostfix(tokens);
    long long result = evaluatePostfix(postfix);

    cout << "\nEquação final: " << equation << " = " << result << endl;

    system("pause");
    return 0;
}