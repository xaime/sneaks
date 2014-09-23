# SNEAKS - Snooping Early Alert Knowledge Service
# - *- coding: utf- 8 - *- .
__author__ = 'Xaime'

import os
import sys
import importlib
import logging
from datetime import datetime, timedelta
from ConfigParser import RawConfigParser
import codecs
from modules.report import *
from operator import itemgetter
import pythoncom
import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import time


class AppServerSvc (win32serviceutil.ServiceFramework):
    """
    Esta es la clase que se usa para que sneaks funcione como un servicio de windows.

    Es el único código dependiente del OS, con lo que portar la aplicación a UNIX solo
    implica sacar el código de main() y colocarlo dentro del código que implemente
    la especificación PEP 3143, "Standard daemon process library". Hay decenas de librerías
    en PyPI que pueden usarse para realizar ésto en muy pocas lineas.
    """
    """
    """
    _svc_name_ = "SNEAKS"
    _svc_display_name_ = "SNEAKS"
    _svc_description_ = "Snooping Early Alert Knowledge Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)
        self.service_stop = False

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.service_stop = True

    def SvcDoRun(self):
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        self.main()

    def main(self):

        class Person:
            def __init__(self, individual):
                self.person = individual
                self.datasources = []
                self.eval_total = []
                self.fetched_data = []
                self.ips = []
                self.detection_data = []
                self.detection = False
                self.alarmed = False
                self.name = u''
                self.notify = False
                self.alarm_threshold = 10
                self.email = ''
                self.prev_alarm_level = 0
                self.enabled = self.__read_config()
                if not self.enabled:
                    logger.critical('Error leyendo la configuración [general] de %s', self.person)
                    exit(1)

            def __read_config(self):
                """
                Obtiene la configuración de la persona de su archivo .person y devuelve True si es válida
                """
                pparser = RawConfigParser()
                with codecs.open("config/" + self.person + '.person', 'r', encoding='utf-8') as cf:
                    pparser.readfp(cf)
                if pparser.has_section("general"):
                    if pparser.has_option('general', 'name'):
                        self.name = pparser.get('general', 'name')
                        if self.name == '':
                            return False
                    else:
                        return False
                    if pparser.has_option('general', 'notify'):
                        self.notify = pparser.getboolean('general', 'notify')
                    if pparser.has_option('general', 'alarm_threshold'):
                        self.alarm_threshold = pparser.getint('general', 'alarm_threshold')
                    if pparser.has_option('general', 'email'):
                        self.email = pparser.get('general', 'email')
                    if self.email == '' and self.notify:
                            return False
                else:
                    return False
                return True

            def get_data(self, downloaded):
                """
                Se obtienen/descargan los datos de cada uno de los plugins
                """
                self.fetched_data = downloaded
                for datasource in self.datasources:
                    if datasource.enabled:
                        datasource.get_data(self.fetched_data)
                        for fetched in datasource.fetched_data:
                            if not self.fetched_data.count(fetched):
                                self.fetched_data.append(fetched)  # Consolidamos la lista de datos ya descargados

            def get_ips(self, ctime_frame, cgiven_time):
                """
                Se obtienen las ips detectadas por los plugins. Algunas ya vendrán marcadas como positivos, otras
                se marcarán como positivas al ser detectadas por dos o más plugins.
                """
                self.ips = []
                for datasource in self.datasources:
                    if datasource.enabled:
                        ips = datasource.get_ips(ctime_frame, cgiven_time)
                        only_ips = [a[0] for a in ips]
                        person_only_ips = [b[0] for b in self.ips]
                        for ip in only_ips:  # Consolidamos una lista de ips detectadas
                            if person_only_ips.count(ip):
                                self.ips[person_only_ips.index(ip)][1] = True  # IP detectada 2 veces, positiva
                            else:
                                self.ips.append(ips[only_ips.index(ip)])  # IP nueva, la añadimos
                return self.ips

            def eval_data(self, ctime_frame, canalyzed_time, cgiven_time, cconfirmed_ips):
                self.detection_data = [0] * canalyzed_time
                for datasource in self.datasources:
                    if datasource.enabled:
                        data = datasource.eval_data(ctime_frame, canalyzed_time, cgiven_time, cconfirmed_ips)
                        for x in range(canalyzed_time):
                            self.detection_data[x] += data[x]  # Suma de todas las evaluaciones de los plugins
                max_detection = max(self.detection_data)
                if max_detection:
                    self.detection = True
                    if max_detection >= person.alarm_threshold:
                        self.alarmed = True
                    else:
                        self.alarmed = False
                else:
                    self.detection = False

            def get_report_data(self, ctime_frame, cgiven_time, cconfirmed_ips):
                report_data = []
                for datasource in self.datasources:
                    if datasource.enabled:
                        data = datasource.get_report_data(ctime_frame, cgiven_time, cconfirmed_ips)
                        if data:
                            dataplusname = [n + [self.name] for n in data]  # se añade el nombre de la persona
                            report_data += dataplusname
                return sorted(report_data, key=itemgetter(0))

        def get_positive_ips(iinterval, itime, ipeople):
            """
            Se obtienen las ips detectadas para cada persona. Algunas ya vendrán marcadas como positivos, otras
            se marcarán como positivas al ser detectadas para dos o más personas.
            """
            people_ips = []
            for iperson in ipeople:
                iperson.get_ips(iinterval, itime)
                person_only_ips = [a[0] for a in iperson.ips]
                people_only_ips = [b[0] for b in people_ips]
                for ip in person_only_ips:  # Consolidamos una lista de ips detectadas
                    if people_only_ips.count(ip):
                        people_ips[people_only_ips.index(ip)][1] = True  # IP detectada 2 veces, se marca como positivo
                    else:
                        people_ips.append(iperson.ips[person_only_ips.index(ip)])  # IP nueva, la añadimos

            ipositive_ips = []
            for ip in people_ips:
                if ip[1]:
                    ipositive_ips.append(ip[0])  # Se genera una lista solo con IPs marcadas como positivos

            return ipositive_ips

        os.chdir(os.path.dirname(os.path.realpath(__file__)))  # Se fija el directorio de trabajo

        # Se inicia el log de la aplicación

        logger = logging.getLogger('sneaks')
        logger.setLevel(logging.DEBUG)
        fh = logging.FileHandler('log/sneaks.log')
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)

        # Se lee sneaks.conf
        parser = RawConfigParser()
        time_frame = 240
        check_interval = 60
        org_alarm_threshold = 10
        min_people_alarm = 2
        admin_email = ''
        with codecs.open('config/sneaks.conf', 'r', encoding='utf-8') as f:
            parser.readfp(f)
        if parser.has_section("general"):
            if parser.has_option('general', 'time_frame'):
                time_frame = parser.getint('general', 'time_frame')
                if time_frame < 1 or time_frame > 1440:
                    logger.critical('Error en sneaks.conf: time_frame')
                    exit(1)
            if parser.has_option('general', 'check_interval'):
                check_interval = parser.getint('general', 'check_interval')
                if check_interval < 1 or check_interval > time_frame:
                    logger.critical('Error en sneaks.conf: check_interval')
                    exit(1)
            if parser.has_option('general', 'org_alarm_threshold'):
                org_alarm_threshold = parser.getint('general', 'org_alarm_threshold')
            if parser.has_option('general', 'min_people_alarm'):
                min_people_alarm = parser.getint('general', 'min_people_alarm')
            if parser.has_option('general', 'admin_email'):
                admin_email = parser.get('general', 'admin_email')
            if admin_email == '':
                logger.critical('Error en sneaks.conf: admin_email')
                exit(1)

        else:
            logger.critical(u'Error en sneaks.conf: falta la sección [general]')
            exit(1)

        # Busca módulos en el directorio plugins los importa. Crea una lista con los plugins importados.
        try:
            plugin_dir = os.listdir('plugins')
            plugin_dir.remove('__init__.py')
            i = 0
            while i < len(plugin_dir):
                if plugin_dir[i].endswith('.py'):
                    plugin_dir[i] = 'plugins.' + plugin_dir[i][:-3]
                    i += 1
                else:
                    plugin_dir.pop(i)
            plugin_dir.sort()
            plugin_list = map(importlib.import_module, plugin_dir)
        except:
            logger.critical('Fallo en la carga de plugins')
            sys.exit(1)

        # Busca ficheros de configuración de persona en el directorio config y devuelve una lista con sus nombres
        person_list = os.listdir('config')
        if person_list != []:
            i = 0
            while i < len(person_list):
                if person_list[i].endswith('.person'):
                    logger.info('%s detectado', person_list[i])
                    person_list[i] = person_list[i][:-7]
                    i += 1
                else:
                    person_list.pop(i)
        else:
            logger.critical(u'No se encuentra ningún archivo de configuración .person')
            exit(1)

        # Se crea la lista de objetos de clase Person. Cada uno se corresponde con una persona vigilada.
        people = []
        for user in person_list:
            people.append(Person(user))

        # Se asocia una lista de objetos de clase [plugin].Datasource a cada persona,
        # aunque solo se usarán aquellos activados
        for person in people:
            for plugin in plugin_list:
                person.datasources.append(plugin.DataSource(person.person))

        temptime = datetime.utcnow()
        timenow = temptime - timedelta(seconds=temptime.second)  # redondeo al segundo 00
        prev_time = datetime(1, 1, 1, 1, 1, 1)
        prev_alarm_level = 0

        while not self.service_stop:

            if timenow > prev_time + timedelta(minutes=check_interval):

                logger.debug(u"Comenzando comprobaciones de SNEAKS")

                downloaded_data = []

                # Se obtienen/descargan los datos de cada persona
                for person in people:
                    person.get_data(downloaded_data)
                    for fet in person.fetched_data:
                        if not downloaded_data.count(fet):
                                    downloaded_data.append(fet)  # Consolidamos la lista de datos ya descargados

                positive_ips = get_positive_ips(time_frame + check_interval, timenow, people)

                # Se generan las las puntuaciones llamando al método eval data de cada persona. Solo se tomarán en
                # cuenta los eventos de IPs positivas, que añadirán su puntuación asociada.
                # Las puntuaciones son una lista con un elemento por cada uno de los últimos 'check_interval'
                # minutos antes de la hora actual. Cada elemento de la lista devuelta contiene el valor acumulado de
                # las detecciones durante el intervalo previo 'timeframe'

                detected_people = 0
                org_eval_data = [0] * check_interval
                for person in people:
                    person.eval_data(time_frame, check_interval, timenow, positive_ips)
                    if person.detection:
                        detected_people += 1
                        for j in range(check_interval):
                            org_eval_data[j] += person.detection_data[j]
                alarm_level = max(org_eval_data)

                # Si se supera el úmbral se envía email con el informe al administrador
                graph_generated = False
                if alarm_level >= org_alarm_threshold and detected_people >= min_people_alarm:

                    logger.info(u"ALARMA nivel " + str(alarm_level) + u" de footprintg para la organización")

                    # si el nivel de alarma sube o abandona la zona de alarma
                    if (org_eval_data[-1] > prev_alarm_level) or (org_eval_data[-1] < org_alarm_threshold):

                        prev_alarm_level = alarm_level

                        # Se generan los gráficos
                        org_report_chart(time_frame, check_interval, timenow, positive_ips,
                                         people, org_alarm_threshold, plugin_dir)
                        graph_generated = True

                        # Se genera el informe de la alarma de la organización
                        save_org_report(time_frame, check_interval, timenow, positive_ips, people,
                                        org_alarm_threshold, plugin_dir, "temp/orgreport.html")

                        # Se envía un email con el informe de la alarma al administrador
                        send_report_mail(admin_email, "temp/orgreport.html",
                                         'Alarma de footprinting ' + timenow.strftime("%Y%m%d%H%M"))

                else:
                    logger.debug(u"Nivel de footprinting de la organización: "
                                 + str(alarm_level) + u". No hay alarma.")

                # Se comprueba si es necesario notificar a algún usuario
                for person in people:
                    if person.alarmed and person.notify:

                        person_alarm_level = max(person.detection_data)

                        logger.info(u"ALARMA nivel " + str(person_alarm_level) + u" de footprintg para " + person.name)

                        # si el nivel de alarma sube o abandona la zona de alarma
                        if (person.detection_data[-1] > person.prev_alarm_level) or \
                                (person.detection_data[-1] < person_alarm_level):

                            person.prev_alarm_level = person_alarm_level

                            if not graph_generated:  # No se han generado los gráficos
                                # Se generan los gráficos
                                org_report_chart(time_frame, check_interval, timenow, positive_ips, people,
                                                 org_alarm_threshold, plugin_dir)

                            # Se genera el informe de la alarma de la persona
                            save_person_report(time_frame, check_interval, timenow, positive_ips, person, plugin_dir,
                                               "temp/" + person.person + "-report.html")

                            # Se envía un email con el informe de la alarma a la persona
                            send_report_mail(person.email, "temp/" + person.person + "-report.html",
                                             'Alarma de footprinting ' + timenow.strftime("%Y%m%d%H%M"))

                    else:
                        logger.debug(u"Nivel de footprinting de " + person.name + u": " +
                                     str(max(person.detection_data)) + u". No hay alarma.")

                prev_time = timenow

            else:
                time.sleep(15)
                temptime = datetime.utcnow()
                timenow = temptime - timedelta(seconds=temptime.second)


if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(AppServerSvc)