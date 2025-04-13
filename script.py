import os
import sys
import datetime
import getpass
import sqlite3
import bcrypt
from tabulate import tabulate

# Configuração do banco de dados
DB_FILE = 'comissoes.db'


# Cores para o terminal
class Cores:
    HEADER = '\033[95m'
    AZUL = '\033[94m'
    VERDE = '\033[92m'
    AMARELO = '\033[93m'
    VERMELHO = '\033[91m'
    ENDC = '\033[0m'
    NEGRITO = '\033[1m'


def limpar_tela():
    """Limpa a tela do terminal"""

    print("\033c", end="")


def pausa():
    """Pausa a execução até o usuário pressionar Enter"""
    input("\nPressione Enter para continuar...")


def verificar_dependencias():
    """Verifica se as dependências necessárias estão instaladas"""
    try:
        import bcrypt
        from tabulate import tabulate
        return True
    except ImportError as e:
        print(f"Erro: Dependência ausente ({e}). Instale com 'pip install bcrypt tabulate'")
        return False


def criar_tabelas():
    """Cria as tabelas no banco de dados se não existirem"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Tabela de usuários
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            tipo TEXT NOT NULL CHECK(tipo IN ('funcionario', 'gestor'))
        )''')

        # Tabela de viagens
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS viagens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            funcionario_id INTEGER NOT NULL,
            destino TEXT NOT NULL,
            distancia REAL NOT NULL CHECK(distancia > 0),
            data TEXT NOT NULL,
            FOREIGN KEY (funcionario_id) REFERENCES usuarios (id) ON DELETE CASCADE
        )''')

        # Tabela de comissões
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS comissoes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            funcionario_id INTEGER NOT NULL,
            valor REAL NOT NULL,
            status TEXT DEFAULT 'pendente' CHECK(status IN ('pendente', 'calculado', 'pago')),
            FOREIGN KEY (funcionario_id) REFERENCES usuarios (id) ON DELETE CASCADE
        )''')

        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"{Cores.VERMELHO}Erro ao criar tabelas: {e}{Cores.ENDC}")
        return False
    finally:
        conn.close()


def hash_senha(senha):
    """Cria um hash para a senha"""
    return bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()


def verificar_senha(senha, hash_senha):
    """Verifica se a senha está correta"""
    return bcrypt.checkpw(senha.encode(), hash_senha.encode())


def cadastrar_usuario():
    """Cadastra um novo usuário no sistema"""
    limpar_tela()
    print(f"{Cores.HEADER}===== CADASTRO DE USUÁRIO ====={Cores.ENDC}")

    # Validação do nome
    while True:
        nome = input("Nome: ").strip()
        if not nome:
            print(f"{Cores.VERMELHO}Nome não pode estar vazio!{Cores.ENDC}")
            continue
        break

    # Validação do email
    while True:
        email = input("Email: ").strip()
        if not email:
            print(f"{Cores.VERMELHO}Email não pode estar vazio!{Cores.ENDC}")
            continue
        if '@' not in email:
            print(f"{Cores.VERMELHO}Email inválido! Deve conter '@'.{Cores.ENDC}")
            continue
        break

    # Validação da senha
    while True:
        # No PyCharm, getpass pode não funcionar corretamente, então usar input normal
        senha = input("Senha (mínimo 4 caracteres): ")
        if len(senha) < 4:
            print(f"{Cores.VERMELHO}Senha muito curta! Use pelo menos 4 caracteres.{Cores.ENDC}")
            continue
        break

    # Validação do tipo de usuário
    while True:
        tipo = input("Tipo (funcionario/gestor): ").lower().strip()
        if tipo in ['funcionario', 'gestor']:
            break
        print(f"{Cores.VERMELHO}Tipo inválido! Use 'funcionario' ou 'gestor'.{Cores.ENDC}")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Verifica se email já existe
        cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
        if cursor.fetchone():
            print(f"{Cores.VERMELHO}Email já cadastrado!{Cores.ENDC}")
            conn.close()
            pausa()
            return

        # Insere o novo usuário
        senha_hash = hash_senha(senha)
        cursor.execute(
            "INSERT INTO usuarios (nome, email, senha, tipo) VALUES (?, ?, ?, ?)",
            (nome, email, senha_hash, tipo)
        )

        conn.commit()
        print(f"{Cores.VERDE}Usuário cadastrado com sucesso!{Cores.ENDC}")
    except sqlite3.Error as e:
        print(f"{Cores.VERMELHO}Erro ao cadastrar usuário: {e}{Cores.ENDC}")
    finally:
        conn.close()
    pausa()


def fazer_login():
    """Realiza o login do usuário"""
    limpar_tela()
    print(f"{Cores.HEADER}===== LOGIN ====={Cores.ENDC}")

    email = input("Email: ").strip()
    # No PyCharm, getpass pode não funcionar corretamente, então usar input normal
    senha = input("Senha: ")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute("SELECT id, nome, senha, tipo FROM usuarios WHERE email = ?", (email,))
        usuario = cursor.fetchone()

        if usuario and verificar_senha(senha, usuario[2]):
            print(f"{Cores.VERDE}Login realizado com sucesso!{Cores.ENDC}")
            conn.close()
            pausa()
            return {"id": usuario[0], "nome": usuario[1], "tipo": usuario[3]}

        print(f"{Cores.VERMELHO}Credenciais inválidas!{Cores.ENDC}")
    except sqlite3.Error as e:
        print(f"{Cores.VERMELHO}Erro ao fazer login: {e}{Cores.ENDC}")
    finally:
        conn.close()
    pausa()
    return None


def registrar_viagem(usuario_id):
    """Registra uma nova viagem para o funcionário"""
    limpar_tela()
    print(f"{Cores.HEADER}===== REGISTRAR VIAGEM ====={Cores.ENDC}")

    # Validação do destino
    while True:
        destino = input("Destino: ").strip()
        if not destino:
            print(f"{Cores.VERMELHO}Destino não pode estar vazio!{Cores.ENDC}")
            continue
        break

    # Validação da distância
    while True:
        try:
            distancia_str = input("Distância (km): ").replace(',', '.')
            distancia = float(distancia_str)
            if distancia <= 0:
                raise ValueError
            break
        except ValueError:
            print(f"{Cores.VERMELHO}Digite um valor numérico válido maior que zero!{Cores.ENDC}")

    data_atual = datetime.date.today().isoformat()

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO viagens (funcionario_id, destino, distancia, data) VALUES (?, ?, ?, ?)",
            (usuario_id, destino, distancia, data_atual)
        )

        conn.commit()
        print(f"{Cores.VERDE}Viagem registrada com sucesso!{Cores.ENDC}")
    except sqlite3.Error as e:
        print(f"{Cores.VERMELHO}Erro ao registrar viagem: {e}{Cores.ENDC}")
    finally:
        conn.close()
    pausa()


def listar_viagens(usuario_id=None):
    """Lista as viagens cadastradas"""
    limpar_tela()
    print(f"{Cores.HEADER}===== VIAGENS CADASTRADAS ====={Cores.ENDC}")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        if usuario_id:
            cursor.execute(
                """
                SELECT v.id, u.nome, v.destino, v.distancia, v.data
                FROM viagens v
                JOIN usuarios u ON v.funcionario_id = u.id
                WHERE v.funcionario_id = ?
                ORDER BY v.data DESC
                """,
                (usuario_id,)
            )
        else:
            cursor.execute(
                """
                SELECT v.id, u.nome, v.destino, v.distancia, v.data
                FROM viagens v
                JOIN usuarios u ON v.funcionario_id = u.id
                ORDER BY u.nome, v.data DESC
                """
            )

        viagens = cursor.fetchall()

        if not viagens:
            print(f"{Cores.AMARELO}Nenhuma viagem encontrada.{Cores.ENDC}")
            conn.close()
            pausa()
            return

        # Formata os dados para exibição
        headers = ["ID", "Funcionário", "Destino", "Distância (km)", "Data"]
        formatted_viagens = [(v[0], v[1], v[2], f"{v[3]:.2f}", v[4]) for v in viagens]

        print(tabulate(formatted_viagens, headers=headers, tablefmt="grid"))
    except sqlite3.Error as e:
        print(f"{Cores.VERMELHO}Erro ao listar viagens: {e}{Cores.ENDC}")
    finally:
        conn.close()
    pausa()


def listar_funcionarios():
    """Lista todos os funcionários cadastrados"""
    limpar_tela()
    print(f"{Cores.HEADER}===== FUNCIONÁRIOS CADASTRADOS ====={Cores.ENDC}")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, nome, email FROM usuarios WHERE tipo = 'funcionario' ORDER BY nome"
        )

        funcionarios = cursor.fetchall()

        if not funcionarios:
            print(f"{Cores.AMARELO}Nenhum funcionário cadastrado.{Cores.ENDC}")
            conn.close()
            pausa()
            return []

        headers = ["ID", "Nome", "Email"]
        print(tabulate(funcionarios, headers=headers, tablefmt="grid"))
        conn.close()
        return funcionarios
    except sqlite3.Error as e:
        print(f"{Cores.VERMELHO}Erro ao listar funcionários: {e}{Cores.ENDC}")
        conn.close()
        pausa()
        return []


def calcular_comissao():
    """Calcula a comissão para um funcionário"""
    funcionarios = listar_funcionarios()
    if not funcionarios:
        return

    while True:
        try:
            func_id = int(input("\nDigite o ID do funcionário (0 para cancelar): "))
            if func_id == 0:
                return
            if func_id not in [f[0] for f in funcionarios]:
                print(f"{Cores.VERMELHO}ID de funcionário inválido!{Cores.ENDC}")
                continue
            break
        except ValueError:
            print(f"{Cores.VERMELHO}Digite um número válido!{Cores.ENDC}")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        # Verifica se já existe comissão calculada para o funcionário
        cursor.execute(
            "SELECT COUNT(*) FROM comissoes WHERE funcionario_id = ? AND status = 'calculado'",
            (func_id,)
        )
        if cursor.fetchone()[0] > 0:
            print(f"{Cores.AMARELO}Atenção: Já existe uma comissão calculada para este funcionário.{Cores.ENDC}")
            continuar = input("Deseja calcular outra? (s/n): ").lower()
            if continuar != 's':
                conn.close()
                pausa()
                return

        # Verifica se há viagens para o funcionário
        cursor.execute("SELECT COUNT(*) FROM viagens WHERE funcionario_id = ?", (func_id,))
        if cursor.fetchone()[0] == 0:
            print(f"{Cores.VERMELHO}Nenhuma viagem encontrada para esse funcionário!{Cores.ENDC}")
            conn.close()
            pausa()
            return

        cursor.execute("SELECT SUM(distancia) FROM viagens WHERE funcionario_id = ?", (func_id,))
        total_distancia = cursor.fetchone()[0]

        valor_comissao = total_distancia * 0.5

        cursor.execute(
            "INSERT INTO comissoes (funcionario_id, valor, status) VALUES (?, ?, ?)",
            (func_id, valor_comissao, "calculado")
        )

        conn.commit()
        cursor.execute("SELECT nome FROM usuarios WHERE id = ?", (func_id,))
        nome_funcionario = cursor.fetchone()[0]

        print(f"\n{Cores.VERDE}Comissão calculada com sucesso!{Cores.ENDC}")
        print(f"Funcionário: {nome_funcionario}")
        print(f"Distância total: {total_distancia:.2f} km")
        print(f"Valor da comissão: R$ {valor_comissao:.2f}")
    except sqlite3.Error as e:
        print(f"{Cores.VERMELHO}Erro ao calcular comissão: {e}{Cores.ENDC}")
    finally:
        conn.close()
    pausa()


def atualizar_status_comissao():
    """Atualiza o status de uma comissão"""
    listar_comissoes()
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        while True:
            try:
                comissao_id = int(input("\nDigite o ID da comissão para atualizar (0 para cancelar): "))
                if comissao_id == 0:
                    conn.close()
                    return
                cursor.execute("SELECT * FROM comissoes WHERE id = ?", (comissao_id,))
                if not cursor.fetchone():
                    print(f"{Cores.VERMELHO}ID de comissão inválido!{Cores.ENDC}")
                    continue
                break
            except ValueError:
                print(f"{Cores.VERMELHO}Digite um número válido!{Cores.ENDC}")

        while True:
            status = input("Novo status (pendente/calculado/pago): ").lower()
            if status in ['pendente', 'calculado', 'pago']:
                break
            print(f"{Cores.VERMELHO}Status inválido! Use 'pendente', 'calculado' ou 'pago'.{Cores.ENDC}")

        cursor.execute("UPDATE comissoes SET status = ? WHERE id = ?", (status, comissao_id))
        conn.commit()
        print(f"{Cores.VERDE}Status da comissão atualizado para {status}!{Cores.ENDC}")
    except sqlite3.Error as e:
        print(f"{Cores.VERMELHO}Erro ao atualizar status: {e}{Cores.ENDC}")
    finally:
        conn.close()
    pausa()


def listar_comissoes():
    """Lista todas as comissões calculadas"""
    limpar_tela()
    print(f"{Cores.HEADER}===== COMISSÕES CALCULADAS ====={Cores.ENDC}")

    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT c.id, u.nome, c.valor, c.status
            FROM comissoes c
            JOIN usuarios u ON c.funcionario_id = u.id
            ORDER BY u.nome
            """
        )

        comissoes = cursor.fetchall()

        if not comissoes:
            print(f"{Cores.AMARELO}Nenhuma comissão calculada.{Cores.ENDC}")
            conn.close()
            pausa()
            return

        headers = ["ID", "Funcionário", "Valor (R$)", "Status"]
        formatted_comissoes = [(c[0], c[1], f"{c[2]:.2f}", c[3]) for c in comissoes]
        print(tabulate(formatted_comissoes, headers=headers, tablefmt="grid"))
    except sqlite3.Error as e:
        print(f"{Cores.VERMELHO}Erro ao listar comissões: {e}{Cores.ENDC}")
    finally:
        conn.close()
    pausa()


def menu_funcionario(usuario):
    """Menu para usuários do tipo funcionário"""
    while True:
        limpar_tela()
        print(f"{Cores.HEADER}===== SISTEMA DE COMISSÕES =====")
        print(f"Usuário: {usuario['nome']} (Funcionário){Cores.ENDC}\n")

        print("1. Registrar Viagem")
        print("2. Visualizar Minhas Viagens")
        print("0. Sair")

        opcao = input("\nEscolha uma opção: ")

        if opcao == "1":
            registrar_viagem(usuario["id"])
        elif opcao == "2":
            listar_viagens(usuario["id"])
        elif opcao == "0":
            break
        else:
            print(f"{Cores.VERMELHO}Opção inválida!{Cores.ENDC}")
            pausa()


def menu_gestor(usuario):
    """Menu para usuários do tipo gestor"""
    while True:
        limpar_tela()
        print(f"{Cores.HEADER}===== SISTEMA DE COMISSÕES =====")
        print(f"Usuário: {usuario['nome']} (Gestor){Cores.ENDC}\n")

        print("1. Listar Funcionários")
        print("2. Listar Todas as Viagens")
        print("3. Calcular Comissão")
        print("4. Listar Comissões")
        print("5. Atualizar Status de Comissão")
        print("0. Sair")

        opcao = input("\nEscolha uma opção: ")

        if opcao == "1":
            listar_funcionarios()
            pausa()
        elif opcao == "2":
            listar_viagens()
        elif opcao == "3":
            calcular_comissao()
        elif opcao == "4":
            listar_comissoes()
        elif opcao == "5":
            atualizar_status_comissao()
        elif opcao == "0":
            break
        else:
            print(f"{Cores.VERMELHO}Opção inválida!{Cores.ENDC}")
            pausa()


def menu_principal():
    """Menu principal do sistema"""
    while True:
        limpar_tela()
        print(f"{Cores.HEADER}===== SISTEMA DE COMISSÕES ====={Cores.ENDC}\n")

        print("1. Login")
        print("2. Cadastrar Usuário")
        print("0. Sair")

        opcao = input("\nEscolha uma opção: ")

        if opcao == "1":
            usuario = fazer_login()
            if usuario:
                if usuario["tipo"] == "funcionario":
                    menu_funcionario(usuario)
                else:
                    menu_gestor(usuario)
        elif opcao == "2":
            cadastrar_usuario()
        elif opcao == "0":
            limpar_tela()
            print(f"{Cores.VERDE}Obrigado por usar o Sistema de Comissões!{Cores.ENDC}")
            sys.exit(0)
        else:
            print(f"{Cores.VERMELHO}Opção inválida!{Cores.ENDC}")
            pausa()


if __name__ == "__main__":
    # Verificar dependências
    if not verificar_dependencias():
        sys.exit(1)

    # Criar as tabelas do banco de dados, se necessário
    if not criar_tabelas():
        print(f"{Cores.VERMELHO}Erro ao inicializar o banco de dados. O programa será encerrado.{Cores.ENDC}")
        sys.exit(1)

    # Iniciar o menu principal
    try:
        menu_principal()
    except KeyboardInterrupt:
        limpar_tela()
        print(f"\n{Cores.AMARELO}Programa encerrado pelo usuário.{Cores.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Cores.VERMELHO}Erro inesperado: {e}{Cores.ENDC}")
        sys.exit(1)