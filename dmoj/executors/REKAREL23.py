from typing import List

from dmoj.executors.rekarel_executor import KarelExecutor


class Executor(KarelExecutor):
    compiler = 'rekarel'
    vm = 'karel'

    test_program = """\
usa rekarel.globales;
iniciar-programa
	inicia-ejecucion
		{ TODO poner codigo aqui }
		apagate;
	termina-ejecucion
finalizar-programa"""
