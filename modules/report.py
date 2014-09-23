# - *- coding: utf- 8 - *- .
# SNEAKS - Snooping Early Alert Knowledge Service

from datetime import timedelta
from boomslang import *
import math
import pygeoip
import socket
from ConfigParser import RawConfigParser
import html2text
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import codecs
import logging
import re
import smtplib
from operator import itemgetter


def tagreplace(tag, html, replacehtml):
    """
    Reemplaza el texto contenido entre <!--tag--> y <!--/tag--> por replacehtml
    """
    t1 = html.index("<!--" + tag + "-->")
    t2 = html.index("<!--/" + tag + "-->")
    return html[:t1] + replacehtml + html[t2 + len(tag) + 8:]


def tagdelete(tag, html):
    """
    Elimina el texto contenido entre <!--tag--> y <!--/tag-->
    """
    t1 = html.index("<!--" + tag + "-->")
    t2 = html.index("<!--/" + tag + "-->")
    return html[:t1] + html[t2 + len(tag) + 8:]


def org_report_chart(rtime_frame, rinterval, rtime, rips, people, org_alarm_threshold, plugin_dir):
    """
    Genera los gráficos de footprinting de la organización y todas las personas con detecciones
    y los guarda en la carpeta temp
    """
    detected_persons = 0
    person_index = []
    pinterval = rinterval + rtime_frame

    rorg_eval_data = [0] * pinterval
    for rperson in people:
        rperson.eval_data(rtime_frame, pinterval, rtime, rips)
        if rperson.detection:
            person_index.append(people.index(rperson))
            detected_persons += 1
            for j in range(pinterval):
                rorg_eval_data[j] += rperson.detection_data[j]

    datemin = rtime - timedelta(minutes=(pinterval - 1))
    datelist = []
    for i in range(pinterval):
        datelist.append(datemin + timedelta(minutes=i))
    dateidx = range(len(rorg_eval_data))

    orgplot = Plot()
    orgplot.yLimits = (0, max(rorg_eval_data) + 10)
    orgplot.xLimits = (0, max(dateidx))
    orgplot.grid.visible = True
    orgplot.title = u"Nivel de footprinting sobre la organización"
    orgplot.yLabel = u"Valor acumulado en los últimos " + str(rtime_frame) + " minutos"
    orgplot.yLabelProperties = {"color":"#808080", "fontsize": 10}


    # relleno gris claro del intervalo completo
    orgline_fill = StackedLines()
    orgline_fill1 = Line()
    orgline_fill1.xValues = dateidx
    orgline_fill1.yValues = rorg_eval_data
    orgline_fill1.lineWidth = 0
    points = [dateidx[datelist.index(c)] for c in datelist if c.minute in {0, 30}]
    labels = [c.strftime("%H:%M") for c in datelist if c.minute in {0, 30}]
    if len(points) > 24:
        points = [dateidx[datelist.index(c)] for c in datelist if c.minute == 0]
        labels = [c.strftime("%H:%M") for c in datelist if c.minute == 0]
    orgline_fill.xTickLabelPoints = points
    orgline_fill.xTickLabels = labels
    orgline_fill.xTickLabelProperties = {"rotation": 45, "fontsize": 10}
    orgline_fill.addLine(orgline_fill1, color="#E6E6E6")
    orgplot.add(orgline_fill)

    # linea intermintente del intervalo completo
    orgline_p = Line()
    orgline_p.xValues = dateidx
    orgline_p.yValues = rorg_eval_data
    orgline_p.lineStyle = "--"
    orgline_p.color = "#B2B2B2"
    orgplot.add(orgline_p)

    # relleno rojo del intervalo analizado
    orgline_fill_p = StackedLines()
    orgline_fill_p1 = Line()
    orgline_fill_p1.xValues = dateidx[rtime_frame:]
    orgline_fill_p1.yValues = rorg_eval_data[rtime_frame:]
    orgline_fill_p1.lineWidth = 0
    orgline_fill_p.addLine(orgline_fill_p1, color="#FF0000")
    orgplot.add(orgline_fill_p)

    # Se añade la linea sólida de nivel acumulado para "rinterval"
    orgline_s = Line()
    orgline_s.xValues = dateidx[rtime_frame:]
    orgline_s.yValues = rorg_eval_data[rtime_frame:]
    orgline_s.lineWidth = 2
    orgplot.add(orgline_s)

    # Se añade la linea de umbral y su etiqueta
    torgline = Line()
    torgline.xValues = dateidx
    torgline.yValues = [org_alarm_threshold]*pinterval
    torgline.lineStyle = "--"
    torgline.color = 'r'
    orgplot.add(torgline)

    tlabel = Label(len(dateidx)/12, org_alarm_threshold + ((max(rorg_eval_data) + 10)/50),
                   "Umbral (" + str(org_alarm_threshold) + ")")

    orgplot.add(tlabel)

    # relleno azul del intervalo analizado por debajo del umbral
    orgline_fill_u = StackedLines()
    orgline_fill_u1 = Line()
    orgline_fill_u1.xValues = dateidx[rtime_frame:]
    temp = rorg_eval_data[rtime_frame:]
    for i in range(len(temp)):
        if temp[i] > org_alarm_threshold:
            temp[i] = org_alarm_threshold
    orgline_fill_u1.yValues = temp
    orgline_fill_u1.lineWidth = 0
    orgline_fill_u.addLine(orgline_fill_u1, color="#3399FF")
    orgplot.add(orgline_fill_u)

    # Se añade la linea vertical que marca el intervalo analizado
    vline1 = VLine()
    vline1.xValues = \
        [dateidx[datelist.index(c)] for c in datelist if
         (c.minute == (rtime - timedelta(minutes=rinterval - 1)).minute
          and c.hour == (rtime - timedelta(minutes=rinterval - 1)).hour)]
    vline1.color = 'b'
    vline1.lineStyle = ":"
    orgplot.add(vline1)

    rorg_eval_data_polar = [0]*len(plugin_dir)
    for i in person_index:
        for j in range(len(plugin_dir)):
            rorg_eval_data_polar[j] += max(people[i].datasources[j].eval_data(rtime_frame, rinterval, rtime, rips))

    # Se dibuja la proyección de tipo radar
    radarplot = Plot()
    radarplot.projection = 'polar'
    radarplot.title = u"Valor máximo por origen de detección"
    radarplot.yLimits = (0, max(rorg_eval_data_polar) + 2)
    radarplot.grid.color = "#A1A1A1"
    radarplot.grid.visible = True
    radarplot.grid.style = "--"
    lineradar = Line()
    t = len(plugin_dir)
    lineradar.yValues = rorg_eval_data_polar + [rorg_eval_data_polar[0]]
    lineradar.xValues = [(2*math.pi/t)*x for x in range(t)] + [2*math.pi]
    lineradar.xTickLabelPoints = [(2*math.pi/t)*x for x in range(t)]
    lineradar.xTickLabels = [p[8:] for p in plugin_dir]
    lineradar.xTickLabelProperties = {"color": "#006600", "alpha": 0.8}
    lineradar.lineWidth = 2
    lineradar.color = "r"
    radarscat = Scatter()
    radarscat.xValues = lineradar.xValues
    radarscat.yValues = lineradar.yValues
    radarscat.markerSize = 25
    radarscat.marker = "s"
    radarplot.add(lineradar)
    radarplot.add(radarscat)

    orgplot.setDimensions(8, 5, dpi=75)
    radarplot.setDimensions(5, 5, dpi=50)

    orgplot.save("temp/imgchart_org.png")
    radarplot.save("temp/imgradar_org.png")

    # Ahora se comienza con el dibujo de las gráficas para cada pesona con detecciones
    personplot = []
    personline_fill = []
    personline_fill1 = []
    personline_p = []
    personline_fill_p = []
    personline_fill_p1 = []
    personline_s = []
    tpersonline = []
    tplabel = []
    personline_fill_u = []
    personline_fill_u1 = []
    vline = []
    pradarplot = []
    plineradar = []
    pradarscat = []
    for idx in person_index:
        people[idx].eval_data(rtime_frame, pinterval, rtime, rips)
        p_eval_data = people[idx].detection_data

        personplot.append(Plot())
        personplot[-1].yLimits = orgplot.yLimits
        personplot[-1].xLimits = orgplot.xLimits
        personplot[-1].grid.visible = True
        personplot[-1].title = "Nivel de footprinting sobre " + people[idx].name
        personplot[-1].yLabel = orgplot.yLabel
        personplot[-1].yLabelProperties = orgplot.yLabelProperties

        # relleno gris claro del intervalo completo
        personline_fill.append(StackedLines())
        personline_fill1.append(Line())
        personline_fill1[-1].xValues = dateidx
        personline_fill1[-1].yValues = p_eval_data
        personline_fill1[-1].lineWidth = 0
        personline_fill[-1].xTickLabelPoints = orgline_fill.xTickLabelPoints
        personline_fill[-1].xTickLabels = orgline_fill.xTickLabels
        personline_fill[-1].xTickLabelProperties = orgline_fill.xTickLabelProperties
        personline_fill[-1].addLine(personline_fill1[-1], color="#E6E6E6")
        personplot[-1].add(personline_fill[-1])

        # linea intermintente del intervalo completo
        personline_p.append(Line())
        personline_p[-1].xValues = dateidx
        personline_p[-1].yValues = p_eval_data
        personline_p[-1].lineStyle = "--"
        personline_p[-1].color = "#B2B2B2"
        personplot[-1].add(personline_p[-1])

        # relleno rojo del intervalo analizado
        personline_fill_p.append(StackedLines())
        personline_fill_p1.append(Line())
        personline_fill_p1[-1].xValues = orgline_fill_p1.xValues
        personline_fill_p1[-1].yValues = p_eval_data[rtime_frame:]
        personline_fill_p1[-1].lineWidth = 0
        personline_fill_p[-1].addLine(personline_fill_p1[-1], color="#FF8080")
        personplot[-1].add(personline_fill_p[-1])

        # Se añade la linea sólida de nivel acumulado para "rinterval"
        personline_s.append(Line())
        personline_s[-1].xValues = orgline_s.xValues
        personline_s[-1].yValues = p_eval_data[rtime_frame:]
        personline_s[-1].lineWidth = 2
        personline_s[-1].color = "#666666"
        personplot[-1].add(personline_s[-1])

        # Se añade la linea de umbral y su etiqueta
        tpersonline.append(Line())
        tpersonline[-1].xValues = dateidx
        tpersonline[-1].yValues = [people[idx].alarm_threshold]*pinterval
        tpersonline[-1].lineStyle = "--"
        tpersonline[-1].color = 'r'
        personplot[-1].add(tpersonline[-1])

        tplabel.append(Label(len(dateidx)/7, people[idx].alarm_threshold + ((max(rorg_eval_data) + 10)/50),
                             "Umbral personal (" + str(people[idx].alarm_threshold) + ")"))
        personplot[-1].add(tplabel[-1])


        # relleno azul del intervalo analizado por debajo del umbral
        personline_fill_u.append(StackedLines())
        personline_fill_u1.append(Line())
        personline_fill_u1[-1].xValues = dateidx[rtime_frame:]
        temp = p_eval_data[rtime_frame:]
        for i in range(len(temp)):
            if temp[i] > people[idx].alarm_threshold:
                temp[i] = people[idx].alarm_threshold
        personline_fill_u1[-1].yValues = temp
        personline_fill_u1[-1].lineWidth = 0
        personline_fill_u[-1].addLine(personline_fill_u1[-1], color="#85C2FF")
        personplot[-1].add(personline_fill_u[-1])

        # Se añade la linea vertical que marca el intervalo analizado
        vline.append(VLine())
        vline[-1].xValues = \
            [dateidx[datelist.index(c)] for c in datelist if
             (c.minute == (rtime - timedelta(minutes=rinterval - 1)).minute
              and c.hour == (rtime - timedelta(minutes=rinterval - 1)).hour)]
        vline[-1].color = 'b'
        vline[-1].lineStyle = ":"
        personplot[-1].add(vline[-1])

        pplugin = [p[8:] for p in plugin_dir]
        for ds in people[idx].datasources: # Se eliminan las etiquetas de plugins desactivados
            if not ds.enabled:
                for p in plugin_dir:
                    if str(ds).count(p):
                        pplugin.pop(pplugin.index(p[8:]))
        t = len(pplugin)

        p_eval_data_polar = []
        for j in range(len(people[idx].datasources)):
            if people[idx].datasources[j].enabled:
                p_eval_data_polar.append(max(people[idx].datasources[j].eval_data(rtime_frame, rinterval, rtime, rips)))

        # Se dibuja la proyección de tipo radar
        pradarplot.append(Plot())
        pradarplot[-1].projection = 'polar'
        pradarplot[-1].title = u"Valor máximo por origen de detección\n" + people[idx].name
        pradarplot[-1].yLimits = (0, max(rorg_eval_data_polar) + 2)
        pradarplot[-1].grid.color = "#A1A1A1"
        pradarplot[-1].grid.visible = True
        pradarplot[-1].grid.style = "--"
        plineradar.append(Line())
        plineradar[-1].yValues = p_eval_data_polar + [p_eval_data_polar[0]]
        plineradar[-1].xValues = [(2*math.pi/t)*x for x in range(t)] + [2*math.pi]
        plineradar[-1].xTickLabelPoints = [(2*math.pi/t)*x for x in range(t)]
        plineradar[-1].xTickLabels = pplugin
        plineradar[-1].xTickLabelProperties = {"color": "#006600", "alpha": 0.8}
        plineradar[-1].lineWidth = 2
        plineradar[-1].color = "r"
        pradarscat.append(Scatter())
        pradarscat[-1].xValues = plineradar[-1].xValues
        pradarscat[-1].yValues = plineradar[-1].yValues
        pradarscat[-1].markerSize = 25
        pradarscat[-1].marker = "s"
        pradarplot[-1].add(plineradar[-1])
        pradarplot[-1].add(pradarscat[-1])

        personplot[-1].setDimensions(8, 5, dpi=75)
        pradarplot[-1].setDimensions(5, 5, dpi=50)
        personplot[-1].save("temp/imgchart_" + people[idx].person + ".png")
        pradarplot[-1].save("temp/imgradar_" + people[idx].person + ".png")


def save_org_report(rtime_frame, rinterval, rtime, rips, people, org_alarm_threshold, plugin_dir, filenamesave):
    """
    Genera un informe de eventos de footprinting para la organización
    """
    with open("resources/mail/orgreporttemplate.html", 'r') as f:
        orghtml = f.read()

    detected_persons = 0
    person_index = []
    rorg_eval_data = [0] * rinterval
    for rperson in people:
        rperson.eval_data(rtime_frame, rinterval, rtime, rips)
        if rperson.detection:
            person_index.append(people.index(rperson))
            detected_persons += 1
            for j in range(rinterval):
                rorg_eval_data[j] += rperson.detection_data[j]

    prev_rorg_eval_data = [0] * rinterval
    for rperson in people:
        rperson.eval_data(rtime_frame, rinterval, rtime - timedelta(minutes=rinterval), rips)
        if rperson.detection:
            for j in range(rinterval):
                prev_rorg_eval_data[j] += rperson.detection_data[j]

    orghtml = orghtml.replace('-ORGTHRESHOLD-', str(org_alarm_threshold))

    if max(rorg_eval_data) >= org_alarm_threshold:
        orghtml = orghtml.replace('-TITLE-', "Alarma de Footprinting")
        orghtml = tagdelete("NOALARM", orghtml)
        if max(prev_rorg_eval_data) < org_alarm_threshold:  # Detección nueva
            orghtml = tagdelete("ALARMUP", orghtml)
            orghtml = tagdelete("ALARMDOWN", orghtml)
            orghtml = tagdelete("ALARMSTABLE", orghtml)
            orghtml = orghtml.replace('-CHECKINTERVAL-', str(rinterval))
            orghtml = orghtml.replace('-LEVELMAX-', str(max(rorg_eval_data)))
            levelmaxtime = rtime + timedelta(minutes=rorg_eval_data.index(max(rorg_eval_data)) - rinterval)
            orghtml = orghtml.replace('-LEVELMAXTIME-', levelmaxtime.strftime("%H:%M"))
            idxtt = 0
            for data in rorg_eval_data:
                if data > org_alarm_threshold:
                    idxtt = data
                    break
            timethreshold = rtime + timedelta(minutes=rorg_eval_data.index(idxtt) - rinterval)
            orghtml = orghtml.replace('-TIMETHRESHOLD-', timethreshold.strftime("%H:%M"))
        elif rorg_eval_data[-1] >= org_alarm_threshold:  # Continua la alarma
            orghtml = tagdelete("NEWALARM", orghtml)
            orghtml = tagdelete("ALARMDOWN", orghtml)
            if rorg_eval_data[-1] > prev_rorg_eval_data[-1]:
                orghtml = tagdelete("ALARMSTABLE", orghtml)
            else:
                orghtml = tagdelete("ALARMUP", orghtml)
            orghtml = orghtml.replace('-CHECKINTERVAL-', str(rinterval))
            orghtml = orghtml.replace('-LASTLEVEL-', str(rorg_eval_data[-1]))
        elif rorg_eval_data[-1] < org_alarm_threshold:  # Se acaba la alarma
            orghtml = tagdelete("ALARMUP", orghtml)
            orghtml = tagdelete("NEWALARM", orghtml)
            orghtml = tagdelete("ALARMSTABLE", orghtml)
            orghtml = tagdelete("RUNNINGFOOTPRINTING", orghtml)
            idxtt = 0
            for data in rorg_eval_data[::-1]:
                if data >= org_alarm_threshold:
                    idxtt = data
                    break
            leveldown = rtime + timedelta(minutes=rorg_eval_data.index(idxtt) - rinterval)
            orghtml = orghtml.replace('-LEVELDOWN-', leveldown.strftime("%H:%M"))
    else:
        orghtml = orghtml.replace('-TITLE-', "Informe de Footprinting")
        orghtml = tagdelete("ALARM", orghtml)
        orghtml = orghtml.replace('-DATEMIN-', (rtime - timedelta(minutes=rinterval)).strftime("%H:%M"))
        orghtml = orghtml.replace('-DATEMAX-', rtime.strftime("%H:%M"))

    orghtml = orghtml.replace('-ORGCHART-', "imgchart_org.png")
    orghtml = orghtml.replace('-ORGRADAR-', "imgradar_org.png")

    orghtml = orghtml.replace('-ONUMPER-', str(detected_persons))

    rorg_eval_data_polar = [0]*len(plugin_dir)
    for i in person_index:
        for j in range(len(plugin_dir)):
            rorg_eval_data_polar[j] += max(people[i].datasources[j].eval_data(rtime_frame, rinterval, rtime, rips))


    oplugin = plugin_dir[rorg_eval_data_polar.index(max(rorg_eval_data_polar))]
    orghtml = orghtml.replace('-OPLUGIN-', oplugin[8:])
    orghtml = orghtml.replace('-ONUMIP-', str(len(rips)))

    onumsem = len([a for a in rorg_eval_data_polar if a > 0])
    orghtml = orghtml.replace('-ONUMSEN-', str(onumsem))

    # Iteramos para cada persona
    p1 = orghtml.index("<!--PERSON-->")
    p2 = orghtml.index("<!--/PERSON-->")
    persontemplate = orghtml[p1:p2+14]
    personhtml = ''
    for idx in person_index:
        htmltemp = persontemplate
        htmltemp = htmltemp.replace('-USERNAME-', people[idx].name.encode('ascii', 'xmlcharrefreplace'))
        htmltemp = htmltemp.replace('-USERCHART-', 'imgchart_' + people[idx].person + '.png')
        htmltemp = htmltemp.replace('-USERRADAR-', 'imgradar_' + people[idx].person + '.png')


        pplugin = [p[8:] for p in plugin_dir]
        for ds in people[idx].datasources: # Se eliminan las etiquetas de plugins desactivados
            if not ds.enabled:
                for p in plugin_dir:
                    if str(ds).count(p):
                        pplugin.pop(pplugin.index(p[8:]))

        p_eval_data_polar = []
        for j in range(len(people[idx].datasources)):
            if people[idx].datasources[j].enabled:
                p_eval_data_polar.append(max(people[idx].datasources[j].eval_data(rtime_frame, rinterval, rtime, rips)))

        uplugin = pplugin[p_eval_data_polar.index(max(p_eval_data_polar))]
        htmltemp = htmltemp.replace('-UPLUGIN-', uplugin)

        unumsem = len([a for a in p_eval_data_polar if a > 0])
        htmltemp = htmltemp.replace('-UNUMSEN-', str(unumsem))

        people[idx].eval_data(rtime_frame, rinterval, rtime, rips)
        if people[idx].alarmed:
            if not people[idx].notify:
                htmltemp = tagdelete("UNOTIFY", htmltemp)
            else:
                htmltemp = htmltemp.replace('-UMAIL-', people[idx].email.encode('ascii', 'xmlcharrefreplace'))
        else:
            htmltemp = tagdelete("UALARMED", htmltemp)

        pips = set([d[0] for d in people[idx].get_ips(rinterval + rtime_frame, rtime)])
        if pips:
            unumip =  len(pips.intersection(set(rips)))
        else:
            unumip = 0

        htmltemp = htmltemp.replace('-UNUMIP-', str(unumip))


        personhtml += htmltemp

    orghtml = orghtml.replace(persontemplate, personhtml)

    # Generamos el texto del informe
    report_data = []
    for idx in person_index:
        report_data += people[idx].get_report_data(rinterval + rtime_frame, rtime, rips)
    report_data = sorted(report_data, key=itemgetter(0))  # Se ordena por fecha y hora

    p1 = orghtml.index("<!--DATAROW-->")
    p2 = orghtml.index("<!--/DATAROW-->")
    htmlrow = orghtml[p1:p2+15]
    p1 = orghtml.index("<!--ALTDATAROW-->")
    p2 = orghtml.index("<!--/ALTDATAROW-->")
    htmlaltrow = orghtml[p1:p2+18]


    rawdata = pygeoip.GeoIP('resources/geoip/GeoLiteCity.dat')
    htmltable = ""
    noalt = True
    for data in report_data:
        if noalt:
            datarow = htmlrow
        else:
            datarow = htmlaltrow
        datarow = datarow.replace('-EHOUR-', data[0].strftime("%H:%M"))
        try:
            hostname = str(socket.gethostbyaddr(data[1])[0])
        except:
            hostname = data[1]
        datarow = datarow.replace('-EIP-', hostname)
        datarow = datarow.replace('-EDESCRIPT-', data[2].encode('ascii', 'xmlcharrefreplace'))
        datarow = datarow.replace('-EPLUGIN-', data[3])
        datarow = datarow.replace('-EPERSON-', data[4].encode('ascii', 'xmlcharrefreplace'))
        try:
            ipdata = rawdata.record_by_name(data[1])
            country = ipdata['country_name']
            city = ipdata['city']
            iplocation = (city + ", " + country).encode('ascii', 'xmlcharrefreplace')
        except:
            iplocation = "Desconocida"
        datarow = datarow.replace('-EGEOIP-', iplocation)


        htmltable += datarow

        noalt = not noalt






    orghtml = tagdelete("DATAROW", orghtml)
    orghtml = tagreplace("ALTDATAROW", orghtml, htmltable)


    with open(filenamesave, 'w') as f:
        orghtml = orghtml.decode('utf8', 'xmlcharrefreplace')
        f.write(orghtml.encode('ascii', 'xmlcharrefreplace'))


def save_person_report(rtime_frame, rinterval, rtime, rips, rperson, plugin_dir, filenamesave):
    """
    Genera un informe de eventos de footprinting para una persona
    """
    with open("resources/mail/personreporttemplate.html", 'r') as f:
        personhtml = f.read()

    rperson.eval_data(rtime_frame, rinterval, rtime, rips)
    person_eval_data = rperson.detection_data

    rperson.eval_data(rtime_frame, rinterval, rtime - timedelta(minutes=rinterval), rips)
    prev_person_eval_data = rperson.detection_data

    personhtml = personhtml.replace('-ORGTHRESHOLD-', str(rperson.alarm_threshold))
    personhtml = personhtml.replace('-USERNAME-', rperson.name.encode('ascii', 'xmlcharrefreplace'))

    if max(person_eval_data) >= rperson.alarm_threshold:
        personhtml = personhtml.replace('-TITLE-', "Alarma de Footprinting")
        personhtml = tagdelete("NOALARM", personhtml)
        if max(prev_person_eval_data) < rperson.alarm_threshold:  # Detección nueva
            personhtml = tagdelete("ALARMUP", personhtml)
            personhtml = tagdelete("ALARMDOWN", personhtml)
            personhtml = tagdelete("ALARMSTABLE", personhtml)
            personhtml = personhtml.replace('-CHECKINTERVAL-', str(rinterval))
            personhtml = personhtml.replace('-LEVELMAX-', str(max(person_eval_data)))
            levelmaxtime = rtime + timedelta(minutes=person_eval_data.index(max(person_eval_data)) - rinterval)
            personhtml = personhtml.replace('-LEVELMAXTIME-', levelmaxtime.strftime("%H:%M"))
            idxtt = 0
            for data in person_eval_data:
                if data > rperson.alarm_threshold:
                    idxtt = data
                    break
            timethreshold = rtime + timedelta(minutes=person_eval_data.index(idxtt) - rinterval)
            personhtml = personhtml.replace('-TIMETHRESHOLD-', timethreshold.strftime("%H:%M"))
        elif person_eval_data[-1] >= rperson.alarm_threshold:  # Continua la alarma
            personhtml = tagdelete("NEWALARM", personhtml)
            personhtml = tagdelete("ALARMDOWN", personhtml)
            if person_eval_data[-1] > prev_person_eval_data[-1]:
                personhtml = tagdelete("ALARMSTABLE", personhtml)
            else:
                personhtml = tagdelete("ALARMUP", personhtml)
            personhtml = personhtml.replace('-CHECKINTERVAL-', str(rinterval))
            personhtml = personhtml.replace('-LASTLEVEL-', str(person_eval_data[-1]))
        elif person_eval_data[-1] < rperson.alarm_threshold:  # Se acaba la alarma
            personhtml = tagdelete("ALARMUP", personhtml)
            personhtml = tagdelete("NEWALARM", personhtml)
            personhtml = tagdelete("ALARMSTABLE", personhtml)
            personhtml = tagdelete("RUNNINGFOOTPRINTING", personhtml)
            idxtt = 0
            for data in person_eval_data[::-1]:
                if data >= rperson.alarm_threshold:
                    idxtt = data
                    break
            leveldown = rtime + timedelta(minutes=person_eval_data.index(idxtt) - rinterval)
            personhtml = personhtml.replace('-LEVELDOWN-', leveldown.strftime("%H:%M"))
    else:
        personhtml = personhtml.replace('-TITLE-', "Informe de Footprinting")
        personhtml = tagdelete("ALARM", personhtml)
        personhtml = personhtml.replace('-DATEMIN-', (rtime - timedelta(minutes=rinterval)).strftime("%H:%M"))
        personhtml = personhtml.replace('-DATEMAX-', rtime.strftime("%H:%M"))


    personhtml = personhtml.replace('-USERCHART-', 'imgchart_' + rperson.person + '.png')
    personhtml = personhtml.replace('-USERRADAR-', 'imgradar_' + rperson.person + '.png')

    pplugin = [p[8:] for p in plugin_dir]
    for ds in rperson.datasources: # Se eliminan las etiquetas de plugins desactivados
        if not ds.enabled:
            for p in plugin_dir:
                if str(ds).count(p):
                    pplugin.pop(pplugin.index(p[8:]))



    p_eval_data_polar = []
    for j in range(len(rperson.datasources)):
        if rperson.datasources[j].enabled:
            p_eval_data_polar.append(max(rperson.datasources[j].eval_data(rtime_frame, rinterval, rtime, rips)))

    uplugin = pplugin[p_eval_data_polar.index(max(p_eval_data_polar))]
    personhtml = personhtml.replace('-UPLUGIN-', uplugin)

    unumsem = len([a for a in p_eval_data_polar if a > 0])
    personhtml = personhtml.replace('-UNUMSEN-', str(unumsem))

    rperson.eval_data(rtime_frame, rinterval, rtime, rips)

    pips = set([d[0] for d in rperson.get_ips(rinterval + rtime_frame, rtime)])
    if pips:
        unumip = len(pips.intersection(set(rips)))

    else:
        unumip = 0

    personhtml = personhtml.replace('-UNUMIP-', str(unumip))

    # Generamos el texto del informe

    report_data = rperson.get_report_data(rinterval + rtime_frame, rtime, rips)

    p1 = personhtml.index("<!--DATAROW-->")
    p2 = personhtml.index("<!--/DATAROW-->")
    htmlrow = personhtml[p1:p2+15]
    p1 = personhtml.index("<!--ALTDATAROW-->")
    p2 = personhtml.index("<!--/ALTDATAROW-->")
    htmlaltrow = personhtml[p1:p2+18]

    rawdata = pygeoip.GeoIP('resources/geoip/GeoLiteCity.dat')
    htmltable = ""
    noalt = True
    for data in report_data:
        if noalt:
            datarow = htmlrow
        else:
            datarow = htmlaltrow
        datarow = datarow.replace('-EHOUR-', data[0].strftime("%H:%M"))
        try:
            hostname = str(socket.gethostbyaddr(data[1])[0])
        except:
            hostname = data[1]
        datarow = datarow.replace('-EIP-', hostname)
        datarow = datarow.replace('-EDESCRIPT-', data[2].encode('ascii', 'xmlcharrefreplace'))
        datarow = datarow.replace('-EPLUGIN-', data[3])
        try:
            ipdata = rawdata.record_by_name(data[1])
            country = ipdata['country_name']
            city = ipdata['city']
            iplocation = (city + ", " + country).encode('ascii', 'xmlcharrefreplace')
        except:
            iplocation = "Desconocida"
        datarow = datarow.replace('-EGEOIP-', iplocation)

        htmltable += datarow

        noalt = not noalt

    personhtml = tagdelete("DATAROW", personhtml)
    personhtml = tagreplace("ALTDATAROW", personhtml, htmltable)

    with open(filenamesave, 'w') as f:
        personhtml = personhtml.decode('utf8', 'xmlcharrefreplace')
        f.write(personhtml.encode('ascii', 'xmlcharrefreplace'))


def send_report_mail(mailto, filename, subject):
    """
    Envía un fichero html filename (el informe) a email. Las imágenes se incrustan en el correo (deben estar en
    la misma carpeta que filename. Se genera también una versión en texto del informe para aquellos clientes de
    correo que no soporten html
    """
    logger = logging.getLogger('report.watched_pages')
    parser = RawConfigParser()
    with codecs.open('config/sneaks.conf', 'r', encoding='utf-8') as f:
        parser.readfp(f)

    smtp_email = ''
    smtp_server = ''
    smtp_port = 0
    smtp_user = ''
    smtp_pwd = ''
    if parser.has_option('general', 'smtp_email'):
        smtp_email = parser.get('general', 'smtp_email')
    if not smtp_email:
        logger.critical('Error en sneaks.conf: smtp_email')
        exit(1)
    if parser.has_option('general', 'smtp_server'):
        smtp_server = parser.get('general', 'smtp_server')
    if not smtp_server:
        logger.critical('Error en sneaks.conf: smtp_server')
        exit(1)
    if parser.has_option('general', 'smtp_port'):
        smtp_port = parser.getint('general', 'smtp_port')
    if not smtp_port:
        logger.critical('Error en sneaks.conf: smtp_port')
        exit(1)
    if parser.has_option('general', 'smtp_user'):
        smtp_user = parser.get('general', 'smtp_user')
    if not smtp_user:
        logger.critical('Error en sneaks.conf: smtp_user')
        exit(1)
    if parser.has_option('general', 'smtp_pwd'):
        smtp_pwd = parser.get('general', 'smtp_pwd')
    if not smtp_pwd:
        logger.critical('Error en sneaks.conf: smtp_pwd')
        exit(1)

    with open(filename, 'r') as f:
        orghtml = f.read()
    orgtxt = html2text.html2text(orghtml)

    msgroot = MIMEMultipart('related')
    msgroot['Subject'] = subject
    msgroot['From'] = smtp_email
    msgroot['To'] = mailto
    msgroot.preamble = 'This is a multi-part message in MIME format.'

    # Encapsulate the plain and HTML versions of the message body in an
    # 'alternative' part, so message agents can decide which they want to display.
    msgalternative = MIMEMultipart('alternative')
    msgroot.attach(msgalternative)

    msgtext = MIMEText(orgtxt.encode('ascii', 'xmlcharrefreplace'))
    msgalternative.attach(msgtext)

    pattern = re.compile(r"img\w+.png")
    images = pattern.findall(orghtml)
    msgimages = []
    for image in images:
        orghtml = orghtml.replace(image, "cid:" + image, 1)
        fp = open("temp/" + image, 'rb')
        msgimages.append(MIMEImage(fp.read()))
        fp.close()

    for i in range(len(images)):
        msgimages[i].add_header('Content-ID', "<" + images[i] + ">")
        msgroot.attach(msgimages[i])

    msgtext = MIMEText(orghtml, 'html')
    msgalternative.attach(msgtext)

    # Send the email (this example assumes SMTP authentication is required)

    smtp = smtplib.SMTP(smtp_server, smtp_port)
    try:

        smtp.ehlo()

        # If we can encrypt this session, do it
        if smtp.has_extn('STARTTLS'):
            smtp.starttls()
            smtp.ehlo() # re-identify ourselves over TLS connection

        smtp.login(smtp_user, smtp_pwd)
        smtp.sendmail(smtp_email, mailto, msgroot.as_string())
    finally:
        smtp.quit()


