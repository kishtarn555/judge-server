import errno
import glob
import os
import re
import subprocess
import sys
from collections import deque
from pathlib import Path, PurePath
from typing import Any, Dict, List, Optional, Tuple, Type

from dmoj.cptbox import Debugger, TracedPopen
from dmoj.cptbox.filesystem_policies import ExactDir, ExactFile, FilesystemAccessRule, RecursiveDir
from dmoj.error import CompileError, InternalError
from dmoj.executors.base_executor import AutoConfigOutput, VersionFlags
from dmoj.executors.compiled_executor import CompiledExecutor
from dmoj.executors.mixins import SingleDigitVersionMixin
from dmoj.judgeenv import skip_self_test
from dmoj.result import Result
from dmoj.utils.unicode import utf8bytes, utf8text

# recomment = re.compile(r'/\*.*?\*/', re.DOTALL | re.U)
# restring = re.compile(r''''(?:\\.|[^'\\])'|"(?:\\.|[^"\\])*"''', re.DOTALL | re.U)
# reinline_comment = re.compile(r'//.*?(?=[\r\n])', re.U)
# reclass = re.compile(
#     r'\bpublic\s+(?:strictfp\s+)?(?:(?:abstract|final)\s+)?(?:strictfp\s+)?class\s+([\w$][\w$]*?)\b', re.U
# )
# repackage = re.compile(r'\bpackage\s+([^.;]+(?:\.[^.;]+)*?);', re.U)
# reexception = re.compile(r'7257b50d-e37a-4664-b1a5-b1340b4206c0: (.*?)$', re.U | re.M)

# JAVA_SANDBOX = os.path.abspath(os.path.join(os.path.dirname(__file__), 'java_sandbox.jar'))


# def find_class(source: str) -> str:
#     source = reinline_comment.sub('', restring.sub('', recomment.sub('', source)))
#     class_name = reclass.search(source)
#     if class_name is None:
#         raise CompileError('No public class: your main class must be declared as a "public class"\n')
#     package = repackage.search(source)
#     if package:
#         raise CompileError(f'Invalid package {package.group(1)}: do not declare package\n')
#     return class_name.group(1)


# def handle_procctl(debugger: Debugger) -> bool:
#     P_PID = 0
#     PROC_STACKGAP_CTL = 17
#     PROC_STACKGAP_STATUS = 18
#     return (
#         debugger.arg0 == P_PID
#         and debugger.arg1 == debugger.pid
#         and debugger.arg2 in (PROC_STACKGAP_CTL, PROC_STACKGAP_STATUS)
#     )


class KarelExecutor(CompiledExecutor):
    ext = 'kcode'

    vm: str
    compiler: str
    # nproc = -1
    # fsize = 1048576  # Allow 1 MB for writing crash log.
    # address_grace = 786432

    # jvm_regex: Optional[str] = None
    # _class_name: Optional[str]

    def __init__(self, problem_id: str, source_code: bytes, **kwargs) -> None:
        super().__init__(problem_id, source_code, **kwargs)

    # def get_compile_popen_kwargs(self) -> Dict[str, Any]:
    #     return {'executable': utf8bytes(self.get_compiler())}

    def get_compiled_file(self) -> str:
        return ''

    def get_executable(self) -> str:
        vm = self.get_vm()
        assert vm is not None
        return vm

    # def get_fs(self) -> List[FilesystemAccessRule]:
    #     fs = (
    #         super().get_fs()
    #         + [ExactFile(self._agent_file)]
    #         + [ExactDir(str(parent)) for parent in PurePath(self._agent_file).parents]
    #     )
    #     vm = self.get_vm()
    #     assert vm is not None
    #     vm_parent = Path(os.path.realpath(vm)).parent.parent
    #     vm_config = Path(glob.glob(f'{vm_parent}/**/jvm.cfg', recursive=True)[0])
    #     if vm_config.is_symlink():
    #         fs += [RecursiveDir(os.path.dirname(os.path.realpath(vm_config)))]
    #     return fs

    # def get_write_fs(self) -> List[FilesystemAccessRule]:
    #     assert self._dir is not None
    #     return super().get_write_fs() + [ExactFile(os.path.join(self._dir, 'submission_jvm_crash.log'))]

    # def get_agent_flag(self) -> str:
    #     hints = [*self._hints]
    #     if self.unbuffered:
    #         hints.append('nobuf')
    #     return f'-javaagent:{self._agent_file}={",".join(hints)}'

    #     return [self.problem]

    # def launch(self, *args, **kwargs) -> TracedPopen:
    #     kwargs['orig_memory'], kwargs['memory'] = kwargs['memory'], 0
    #     return super().launch(*args, **kwargs)

    def populate_result(self, stderr: bytes, result: Result, process: TracedPopen) -> None:
        super().populate_result(stderr, result, process)
        if process.is_ir:
            if process.returncode == 20:
                result.result_flag |= Result.MLE
            elif process.returncode >= 48 and process.returncode <= 63:
                result.result_flag |= Result.TLE


    def parse_feedback_from_stderr(self, stderr: bytes, process: TracedPopen) -> str:
        exception = 'Error de juez (Error desconocido)'
        if process.returncode == 2:
            exception = "Error de juez (El administrador del juez debe revisar la versión de la VM)"
        elif process.returncode == 16:
            exception = "Error de ejecución (Karel chocó con un muro)"
        elif process.returncode == 17:
            exception = "Error de ejecución (Karel intentó recoger un zumbador de una posición vacía)"
        elif process.returncode == 18:
            exception = "Error de ejecución (Karel intentó dejar un zumbador con su mochila vacía)"
        elif process.returncode == 19:
            exception = "Error de ejecución (La pila de llamadas se desbordó)"
        elif process.returncode == 20:
            exception = "Límite de memoria (Se excedió la memoria de la pila de llamadas)"
        elif process.returncode == 21:
            exception = "Error de ejecución (Se excedió la cantidad de parámetros permitidos en una llamada)"
        elif process.returncode == 22:
            exception = "Error de ejecución (Un número excedió el límite superior)"
        elif process.returncode == 23:
            exception = "Error de ejecución (Un número excedió el límite inferior)"
        elif process.returncode == 24:
            exception = "Error de ejecución (Un montón excedió el límite superior)"
        elif process.returncode == 25:
            exception = "Error de ejecución (Se excedió el límite superior de la mochila)"
        elif process.returncode == 48:
            exception = "Límite de instrucciones excedido (Demasiadas en general)"
        elif process.returncode == 49:
            exception = "Límite de instrucciones excedido (Demasiadas izquierdas)"
        elif process.returncode == 50:
            exception = "Límite de instrucciones excedido (Demasiados avanzas)"
        elif process.returncode == 51:
            exception = "Límite de instrucciones excedido (Demasiados coge-zumbadores)"
        elif process.returncode == 52:
            exception = "Límite de instrucciones excedido (Demasiados deja-zumbadores)"

        return exception

    @classmethod
    def get_vm(cls) -> Optional[str]:
        return cls.runtime_dict.get(cls.vm)


    @classmethod
    def get_compiler(cls) -> Optional[str]:
        return cls.runtime_dict.get(cls.compiler)

    @classmethod
    def initialize(cls) -> bool:
        vm = cls.get_vm()
        compiler = cls.get_compiler()
        if vm is None or compiler is None:
            return False
        if not os.path.isfile(vm) or not os.path.isfile(compiler):
            return False
        return skip_self_test or cls.run_self_test()

    @classmethod
    def test_jvm(cls, name: str, path: str) -> Tuple[Dict[str, Any], bool, str]:
        raise NotImplementedError()

    @classmethod
    def get_versionable_commands(cls) -> List[Tuple[str, str]]:
        compiler = cls.get_compiler()
        assert compiler is not None
        return [('karel', compiler)]

    def get_compile_args(self) -> List[str]:
        compiler = self.get_compiler()
        assert compiler is not None
        assert self._code is not None
        # TODO: Maybe it needs an output file
        return [compiler, 'compile', self._code]
    # @classmethod
    # def autoconfig(cls) -> AutoConfigOutput:
    #     if cls.jvm_regex is None:
    #         return {}, False, 'Unimplemented', ''

    #     JVM_DIR = '/usr/local' if sys.platform.startswith('freebsd') else '/usr/lib/jvm'
    #     regex = re.compile(cls.jvm_regex)

    #     try:
    #         vms = os.listdir(JVM_DIR)
    #     except OSError:
    #         vms = []

    #     for item in vms:
    #         path = os.path.join(JVM_DIR, item)
    #         if not os.path.isdir(path) or os.path.islink(path):
    #             continue

    #         if regex.match(item):
    #             try:
    #                 config, success, message = cls.test_jvm(item, path)
    #             except (NotImplementedError, TypeError, ValueError):
    #                 return {}, False, 'Unimplemented', ''
    #             else:
    #                 if success:
    #                     return config, success, message, ''
    #     return {}, False, 'Could not find JVM', ''

    # @classmethod
    # def unravel_java(cls, path: str) -> str:
    #     with open(path, 'rb') as f:
    #         if f.read(2) != '#!':
    #             return os.path.realpath(path)

    #     with open(os.devnull, 'w') as devnull:
    #         process = subprocess.Popen(['bash', '-x', path, '-version'], stdout=devnull, stderr=subprocess.PIPE)

    #     log = [i for i in process.communicate()[1].split(b'\n') if b'exec' in i]
    #     cmdline = log[-1].lstrip(b'+ ').split()
    #     return utf8text(cmdline[1]) if len(cmdline) > 1 else os.path.realpath(path)


# class JavacExecutor(KarelExecutor):
    # def create_files(self, problem_id: str, source_code: bytes, *args, **kwargs) -> None:
    #     super().create_files(problem_id, source_code, *args, **kwargs)
    #     # This step is necessary because of Unicode classnames
    #     try:
    #         source = utf8text(source_code)
    #     except UnicodeDecodeError:
    #         raise CompileError('Your UTF-8 is bad, and you should feel bad')
    #     class_name = find_class(source)
    #     self._code = self._file(f'{class_name}.java')
    #     try:
    #         with open(self._code, 'wb') as fo:
    #             fo.write(utf8bytes(source))
    #     except IOError as e:
    #         if e.errno in (errno.ENAMETOOLONG, errno.ENOENT, errno.EINVAL):
    #             raise CompileError('Why do you need a class name so long? As a judge, I sentence your code to death.\n')
    #         raise
    #     self._class_name = class_name

    def get_compile_args(self) -> List[str]:
        compiler = self.get_compiler()
        assert compiler is not None
        assert self._code is not None
        # TODO: Maybe it needs an output file
        return [compiler, 'compile', self._code]

    def handle_compile_error(self, output: bytes):
        if b'is public, should be declared in a file named' in utf8bytes(output):
            raise CompileError('You are a troll. Trolls are not welcome. As a judge, I sentence your code to death.\n')
        raise CompileError(output)

    @classmethod
    def test_jvm(cls, name: str, path: str) -> Tuple[Dict[str, Any], bool, str]:
        vm_path = os.path.join(path, 'bin', 'java')
        compiler_path = os.path.join(path, 'bin', 'javac')

        if os.path.isfile(vm_path) and os.path.isfile(compiler_path):
            # Not all JVMs have the same VMs available; specifically,
            # OpenJDK for ARM has no client VM, but has dcevm+server. So, we test
            # a bunch and if it's not the default (-client), then we list it
            # in the config.
            vm_modes = ['client', 'server', 'dcevm', 'zero']
            cls_vm_mode = cls.vm + '_mode'
            result = {}
            for mode in vm_modes:
                result = {cls.vm: vm_path, cls_vm_mode: mode, cls.compiler: compiler_path}

                executor: Type[JavacExecutor] = type('Executor', (cls,), {'runtime_dict': result})
                success = executor.run_self_test(output=False)
                if success:
                    # Don't pollute the YAML in the usual case where it's -client
                    if mode == 'client':
                        del result[cls_vm_mode]
                    return result, success, f'Using {vm_path} ({mode} VM)'
            else:
                # If absolutely no VM mode works, then we've failed the self test
                return result, False, 'Failed self-test'
        else:
            return {}, False, 'Invalid JDK'
