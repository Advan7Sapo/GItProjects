#include <iostream>
#include <string>
#include <vector>
#include <stack>
#include <cctype>
#include <sstream>

using namespace std;

bool isNumber(const string& s) {
    if (s.empty()) return false;
    size_t start = 0;
    if (s[0] == '-') {
        if (s.size() == 1) return false;
        start = 1;
    }
    for (size_t i = start; i < s.size(); ++i) {
        if (!isdigit(s[i])) return false;
    }
    return true;
}

vector<string> tokenize(const string& equation) {
    vector<string> tokens;
    string currentNumber;
    bool expectOperator = false;

    for (size_t i = 0; i < equation.size(); ++i) {
        char c = equation[i];
        if (isdigit(c) || (c == '-' && (i == 0 || !isdigit(equation[i-1])))) {
            currentNumber += c;
            expectOperator = true;
        } else {
            if (!currentNumber.empty()) {
                tokens.push_back(currentNumber);
                currentNumber.clear();
            }
            if (c == '+' || c == '-' || c == '*' || c == '/' || c == '%') {
                tokens.push_back(string(1, c));
                expectOperator = false;
            }
        }
    }
    if (!currentNumber.empty()) {
        tokens.push_back(currentNumber);
    }
    return tokens;
}

int getPrecedence(const string& op) {
    if (op == "*" || op == "/" || op == "%") return 2;
    if (op == "+" || op == "-") return 1;
    return 0;
}

vector<string> infixToPostfix(const vector<string>& tokens) {
    vector<string> output;
    stack<string> opStack;

    for (const string& token : tokens) {
        if (isNumber(token)) {
            output.push_back(token);
        } else {
            while (!opStack.empty() && getPrecedence(opStack.top()) >= getPrecedence(token)) {
                output.push_back(opStack.top());
                opStack.pop();
            }
            opStack.push(token);
        }
    }

    while (!opStack.empty()) {
        output.push_back(opStack.top());
        opStack.pop();
    }

    return output;
}

long long evaluatePostfix(const vector<string>& postfix) {
    stack<long long> st;
    for (const string& token : postfix) {
        if (isNumber(token)) {
            st.push(stoll(token));
        } else {
            if (st.size() < 2) {
                cerr << "Erro: operandos insuficientes para o operador '" << token << "'" << endl;
                return 0;
            }
            long long b = st.top(); st.pop();
            long long a = st.top(); st.pop();
            if (token == "+") {
                st.push(a + b);
            } else if (token == "-") {
                st.push(a - b);
            } else if (token == "*") {
                st.push(a * b);
            } else if (token == "/") {
                if (b == 0) {
                    cerr << "Erro: divisao por zero" << endl;
                    return 0;
                }
                st.push(a / b);
            } else if (token == "%") {
                if (b == 0) {
                    cerr << "Erro: modulo por zero" << endl;
                    return 0;
                }
                st.push(a % b);
            } else {
                cerr << "Erro: operador desconhecido '" << token << "'" << endl;
                return 0;
            }
        }
    }
    if (st.size() != 1) {
        cerr << "Erro: expressao malformada" << endl;
        return 0;
    }
    return st.top();
}

int main() {
    string equation;
    char c;

    cout << "Digite a equacao (pressione '=' para finalizar):" << endl;

    while (cin >> c && c != '=') {
        equation += c;
        cout << "Equacao atual: " << equation << endl;
    }

    vector<string> tokens = tokenize(equation);
    vector<string> postfix = infixToPostfix(tokens);
    long long result = evaluatePostfix(postfix);

    cout << "Resultado: " << result << endl;

    return 0;
}