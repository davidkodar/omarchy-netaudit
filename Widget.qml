import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
// Colours through a qualified name: a bare Color can be undefined in a plugin.
import qs.Commons as NetCommons
import qs.Ui

// Home network audit in the bar: the last audit score of this computer's own
// router, in the colour of its verdict. Clicking it opens a popup with what to
// fix, every other check and a button to scan again. It scans by itself only
// when the owner switches on "Alert me when something changes"; otherwise it
// just rereads the saved report.
Panel {
  id: root
  moduleName: "davidkodar.netaudit"
  ipcTarget: "davidkodar.netaudit"

  readonly property string helperPath: decodeURIComponent(Qt.resolvedUrl("bin/netaudit").toString().replace(/^file:\/\//, ""))
  readonly property string shield: String.fromCodePoint(0xF0498)

  // Optional "router" setting in shell.json, e.g. "Brand Model", so the
  // agent's steps fit the router. Leave it out and the agent asks.
  readonly property string router: String(root.setting("router", ""))

  // The plugin's own strings, in the language Omarchy is set to.
  NetCommons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  // From the helper: the owner's choices and the Omarchy default agent.
  property string agentName: ""
  property string dnsChoice: "auto"
  property bool watching: false
  property int watchMinutes: 30

  property var report: null
  property string error: ""
  property bool scanning: false
  // Whether the "how to read this" notes are showing in the popup.
  property bool showInfo: false

  readonly property var score: report && report.score ? report.score : null
  readonly property bool hasScore: score !== null && score.provisional !== null && score.provisional !== undefined
  readonly property var rows: buildRows(report)
  readonly property var lastChange: buildChange(report)

  // Traffic-light colours from the active Omarchy theme, so the verdict fits
  // every theme; the fallbacks are used when a theme does not name a colour.
  property color green: "#6fbf73"
  property color yellow: "#e0b84c"
  property color orange: "#e08a4f"
  property color red: NetCommons.Color.urgent

  function loadThemeColors(toml) {
    const wanted = { green: "green", yellow: "yellow", orange: "orange", red: "red" }
    for (const line of String(toml).slice(0, 20000).split("\n")) {
      const m = /^\s*(green|yellow|orange|red)\s*=\s*"(#[0-9a-fA-F]{6})"\s*$/.exec(line)
      if (!m) continue
      // A theme's "green" can be nearly grey. A verdict has to read as a
      // colour, so a washed-out one keeps the fallback instead.
      const c = Qt.color(m[2])
      if (c.hslSaturation >= 0.3) root[wanted[m[1]]] = m[2]
    }
  }

  FileView {
    id: themeFile
    path: NetCommons.Color.currentThemePath + "/colors.toml"
    watchChanges: false
    printErrors: false
    onLoaded: root.loadThemeColors(text())
  }
  // The shell's own colours change when the theme does: reread ours then.
  Connections {
    target: NetCommons.Color
    function onForegroundChanged() { themeFile.reload() }
    function onAccentChanged() { themeFile.reload() }
  }

  // The verdict. The score sets it, and three things cap it: a high finding is
  // never better than red, a medium one never better than orange, and a scan
  // that knows under 60% of the evidence is never green.
  readonly property string verdict: {
    if (!hasScore) return "none"
    const s = score.provisional
    let v = s >= 85 ? 0 : s >= 70 ? 1 : s >= 50 ? 2 : 3
    if (rows.some(r => r.level === "high")) v = Math.max(v, 3)
    else if (rows.some(r => r.level === "medium")) v = Math.max(v, 2)
    if (score.coverage < 60) v = Math.max(v, 1)
    return ["green", "yellow", "orange", "red"][v]
  }
  readonly property string verdictLabel: verdict === "none" ? strings.t("title") : strings.t("verdict." + verdict)
  readonly property color verdictColor: verdict === "none" ? NetCommons.Color.popups.text : root[verdict]

  function levelColor(level) {
    return level === "ok" ? root.green
         : level === "low" ? root.yellow
         : level === "medium" ? root.orange
         : level === "high" ? root.red
         : NetCommons.Color.muted
  }

  visible: true
  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // Everything shown comes from files on disk. They are ours, but bound and
  // check them before display all the same.
  function clip(value, max) {
    return String(value === undefined || value === null ? "" : value).slice(0, max)
  }
  function word(value) {
    const s = clip(value, 40)
    return /^[a-z0-9-]+$/.test(s) ? s : ""
  }

  // A translated string when the catalogue has the key, else the fallback.
  function tr(key, fallback) {
    const value = strings.t(key)
    return value === key ? fallback : value
  }
  function counted(key, count, fallback) {
    const value = strings.tn(key, count)
    return value === key ? fallback : value.arg(NetCommons.I18n.formatNumber(count))
  }

  readonly property var checkOrder: ["tcp-22", "tcp-23", "tcp-80", "tcp-7547", "upnp", "wifi-security", "wifi-wps", "wifi-channel", "dns"]

  function buildRows(r) {
    if (!r || !Array.isArray(r.findings)) return []
    const out = []
    for (const f of r.findings.slice(0, 24)) {
      if (!f || checkOrder.indexOf(f.id) < 0) continue
      const state = word(f.state)
      const fallback = clip(f.summary, 240)
      const key = "finding." + f.id + "." + state
      const summary = typeof f.count === "number" ? counted(key, f.count, fallback) : tr(key, fallback)
      let level = "ok"
      if (f.severity === "HIGH") level = "high"
      else if (f.severity === "MEDIUM") level = "medium"
      else if (f.severity === "LOW") level = "low"
      else if (f.severity === "REVIEW" || state.indexOf("unknown") === 0 || fallback.indexOf("Unknown") === 0) level = "unknown"
      // One or two words for the compact list of checks that need nothing.
      let brief = strings.t("short." + f.id + "." + state)
      if (brief === "short." + f.id + "." + state) brief = strings.t("short." + state)
      if (brief === "short." + state) brief = strings.t(level === "unknown" ? "short.unknown" : "short.ok")
      if (typeof f.count === "number") {
        const plural = strings.tn("short." + f.id + "." + state, f.count)
        if (plural !== "short." + f.id + "." + state) brief = plural.arg(NetCommons.I18n.formatNumber(f.count))
      }
      const fix = f.action ? tr("action." + word(f.actionId), clip(f.action, 240)) : ""
      out.push({ id: f.id, state: state, name: tr("check." + f.id, f.id), summary: summary, brief: brief, fix: fix, level: level })
    }
    return out
  }

  // What needs doing, worst first; and everything else, in a fixed order.
  readonly property var toFix: {
    const rank = { high: 0, medium: 1, low: 2 }
    return rows.filter(r => rank[r.level] !== undefined).sort((a, b) => rank[a.level] - rank[b.level])
  }
  readonly property var unmeasured: rows.filter(r => r.level === "unknown")
  readonly property var settled: rows.filter(r => r.level === "ok")

  // Why the verdict is worse than the number alone would give, when it is.
  readonly property string capNote: {
    if (!hasScore) return ""
    const s = score.provisional
    const byScore = s >= 85 ? "green" : s >= 70 ? "yellow" : s >= 50 ? "orange" : "red"
    if (byScore === verdict) return ""
    if (verdict === "red") return strings.t("cap.high")
    if (verdict === "orange") return strings.t("cap.medium")
    return strings.t("cap.coverage")
  }

  function levelIcon(level) {
    return String.fromCodePoint(level === "ok" ? 0xF05E0 : level === "unknown" ? 0xF02D7 : 0xF0028)
  }

  function formatWhen(iso) {
    const when = new Date(iso)
    if (!iso || isNaN(when.getTime())) return ""
    const locale = Qt.locale(NetCommons.I18n.formatLocale)
    return when.toLocaleDateString(locale, Locale.ShortFormat) + " " + when.toLocaleTimeString(locale, Locale.ShortFormat)
  }

  // The most recent time a check changed, kept on the report until the next.
  function buildChange(r) {
    const c = r ? r.lastChange : null
    if (!c || !Array.isArray(c.items) || c.items.length === 0) return null
    const when = formatWhen(c.at)
    if (when === "") return null
    const lines = c.items.slice(0, 3).map(item => {
      const key = word(item.key), from = word(item.from), to = word(item.to)
      return strings.t("change.item").arg(tr("fact." + key, key)).arg(tr("value." + from, from)).arg(tr("value." + to, to))
    })
    return { title: strings.t("change.line").arg(when), lines: lines }
  }

  function take(text) {
    try {
      const parsed = JSON.parse(text)
      if (parsed && parsed.error) { root.error = clip(parsed.error, 200); return }
      root.error = ""
      root.report = parsed && parsed.findings ? parsed : null
    } catch (e) {
      root.error = strings.t("error.unreadable")
    }
  }

  function takeSettings(text) {
    try {
      const s = JSON.parse(text)
      if (!s || s.error) return
      root.dnsChoice = s.dns === "encrypted" ? "encrypted" : "auto"
      root.watching = s.watch === true
      root.watchMinutes = Math.max(5, Math.min(1440, Number(s.watchMinutes) || 30))
      root.agentName = word(s.agent)
    } catch (e) {}
  }

  // Opens the Omarchy default coding agent in a terminal, on the saved report.
  // `what` is a check id from checkOrder, or "all".
  function explain(what) {
    Quickshell.execDetached([root.helperPath, "explain", what, root.router])
    root.close()
  }

  function scan() {
    if (!scanProc.running && !autoProc.running) scanProc.running = true
  }

  // Changes one of the owner's choices; a DNS change is followed by a scan so
  // the score reflects it at once.
  function choose(name, value) {
    if (setProc.running) return
    setProc.rescan = name === "dns"
    setProc.command = [root.helperPath, "set", name, value]
    setProc.running = true
  }

  function metaLine() {
    if (!report) return strings.t("meta.none")
    const parts = []
    if (score) parts.push(strings.t("meta.coverage").arg(NetCommons.I18n.formatNumber(Math.round(score.coverage))))
    const when = formatWhen(report.generatedAt)
    if (when !== "") parts.push(strings.t("meta.scanned").arg(when))
    return parts.join("\n")
  }

  Process {
    id: readProc
    command: [root.helperPath, "report"]
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: root.take(text) }
  }

  Process {
    id: scanProc
    command: [root.helperPath, "scan"]
    onRunningChanged: root.scanning = running
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: root.take(text) }
  }

  // The background check. The helper does nothing unless watching is on and
  // the report is older than the watch interval, so several bars do not scan
  // several times.
  Process {
    id: autoProc
    command: [root.helperPath, "scan", "auto"]
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: root.take(text) }
  }

  Process {
    id: settingsProc
    command: [root.helperPath, "settings"]
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: root.takeSettings(text) }
  }

  Process {
    id: setProc
    property bool rescan: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.takeSettings(text)
        if (setProc.rescan) root.scan()
      }
    }
  }

  // Reread the saved report and the settings once a minute, and at once when
  // the popup opens.
  Timer {
    interval: 60000
    running: true
    repeat: true
    triggeredOnStart: true
    onTriggered: {
      if (!readProc.running && !scanProc.running && !autoProc.running) readProc.running = true
      if (!settingsProc.running) settingsProc.running = true
    }
  }
  // While watching is on, ask the helper every five minutes whether a scan is
  // due.
  Timer {
    interval: 300000
    running: root.watching
    repeat: true
    onTriggered: if (!scanProc.running && !autoProc.running) autoProc.running = true
  }
  onOpenedChanged: {
    if (!opened) { root.showInfo = false; return }
    if (!readProc.running && !scanProc.running && !autoProc.running) readProc.running = true
    if (!settingsProc.running) settingsProc.running = true
  }

  WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.shield + (root.hasScore ? " " + root.score.provisional : "")
    dimmed: !root.hasScore && !root.opened
    // The verdict colour, so the bar says at a glance whether the network is
    // green; the bar's own colour until there is a scan to judge.
    foreground: root.verdict !== "none"
      ? root.verdictColor
      : (root.bar ? root.bar.barForeground : NetCommons.Color.foreground)
    tooltipText: root.opened ? ""
      : root.hasScore ? strings.t("tooltip.score").arg(root.score.provisional).arg(root.verdictLabel.toLowerCase())
      : strings.t("tooltip.none")
    onPressed: b => { if (b === Qt.LeftButton) root.toggle() }
  }

  KeyboardPanel {
    id: popup
    objectName: "netAuditPopup"
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: body
    contentWidth: popup.fittedContentWidth(Style.space(440))
    contentHeight: popup.fittedContentHeight(content.implicitHeight)

    FocusScope {
      id: body
      anchors.fill: parent
      Keys.onEscapePressed: root.showInfo ? root.showInfo = false : root.close()

      component Plain: Text {
        textFormat: Text.PlainText
        font.family: Style.font.family
        font.pixelSize: Style.font.body
        color: NetCommons.Color.popups.text
        wrapMode: Text.WordWrap
      }

      // A short clickable word beside a check's name.
      component Link: Plain {
        id: link
        signal activated()
        color: NetCommons.Color.accent
        font.underline: linkArea.containsMouse
        MouseArea {
          id: linkArea
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: link.activated()
        }
      }

      // The list scrolls when a long report would not fit the screen.
      Flickable {
        id: flick
        anchors.fill: parent
        contentWidth: width
        contentHeight: content.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        interactive: contentHeight > height

      Column {
        id: content
        readonly property real inner: width - leftPadding - rightPadding
        width: flick.width
        padding: Style.space(14)
        spacing: Style.space(10)

        // Score
        Row {
          id: scoreRow
          spacing: Style.space(12)
          Plain {
            id: big
            visible: root.hasScore
            font.pixelSize: Style.font.display
            color: root.verdictColor
            text: root.hasScore ? root.score.provisional : "–"
          }
          Column {
            anchors.verticalCenter: big.verticalCenter
            width: content.inner - (big.visible ? big.width + Style.space(12) : 0) - infoButton.width - Style.space(12)
            Plain {
              width: parent.width
              color: root.verdictColor
              text: root.hasScore ? strings.t("score.outOf").arg(root.verdictLabel).arg(root.score.provisional) : root.verdictLabel
            }
            Plain { width: parent.width; color: NetCommons.Color.muted; text: root.metaLine() }
          }
          PanelActionButton {
            id: infoButton
            iconText: String.fromCodePoint(0xF02FD)
            tooltipText: root.showInfo ? strings.t("info.hide") : strings.t("info.show")
            foreground: root.showInfo ? NetCommons.Color.accent : NetCommons.Color.popups.text
            onClicked: root.showInfo = !root.showInfo
          }
        }

        // The score as a bar, with marks where the verdict changes.
        Item {
          visible: root.hasScore
          width: content.inner
          height: Style.space(6)
          Rectangle {
            anchors.fill: parent
            radius: height / 2
            color: Qt.rgba(NetCommons.Color.popups.text.r, NetCommons.Color.popups.text.g, NetCommons.Color.popups.text.b, 0.14)
          }
          Rectangle {
            width: parent.width * Math.max(0, Math.min(100, root.hasScore ? root.score.provisional : 0)) / 100
            height: parent.height
            radius: height / 2
            color: root.verdictColor
          }
          Repeater {
            model: [50, 70, 85]
            Rectangle {
              required property int modelData
              x: Math.round(parent.width * modelData / 100)
              width: 2
              height: parent.height
              color: Qt.rgba(NetCommons.Color.popups.background.r, NetCommons.Color.popups.background.g, NetCommons.Color.popups.background.b, 1)
            }
          }
        }

        Plain {
          visible: root.capNote !== ""
          width: content.inner
          font.pixelSize: Style.font.caption
          color: root.verdictColor
          text: root.capNote
        }

        Plain {
          visible: root.error !== ""
          width: content.inner
          color: NetCommons.Color.urgent
          text: root.error
        }

        // To fix: what was found, in a word, and what to do about it.
        PanelSectionHeader {
          visible: root.toFix.length > 0
          text: strings.t("section.toFix").arg(NetCommons.I18n.formatNumber(root.toFix.length))
        }
        Repeater {
          model: root.toFix
          Row {
            id: problem
            required property var modelData
            width: content.inner
            spacing: Style.space(8)
            Plain {
              id: problemIcon
              font.pixelSize: Style.font.icon
              color: root.levelColor(problem.modelData.level)
              text: root.levelIcon(problem.modelData.level)
            }
            Column {
              width: problem.width - problemIcon.width - problem.spacing
              spacing: Style.space(2)
              Item {
                width: parent.width
                height: problemName.height
                Plain { id: problemName; font.bold: true; text: problem.modelData.name }
                Row {
                  anchors.right: parent.right
                  spacing: Style.space(12)
                  Plain { color: root.levelColor(problem.modelData.level); text: problem.modelData.brief }
                  Link {
                    text: strings.t("link.explain")
                    onActivated: root.explain(problem.modelData.id)
                  }
                }
              }
              Plain {
                visible: problem.modelData.fix !== ""
                width: parent.width
                color: NetCommons.Color.muted
                text: problem.modelData.fix
              }
              // DNS is measured on this computer. A router that encrypts DNS
              // for the whole home is something only the owner knows.
              Link {
                visible: problem.modelData.id === "dns" && problem.modelData.state === "plaintext-measured"
                text: strings.t("link.dnsRouter")
                onActivated: root.choose("dns", "encrypted")
              }
            }
          }
        }

        PanelSeparator { width: content.inner; visible: root.toFix.length > 0 && root.unmeasured.length + root.settled.length > 0 }

        // One line each: first what could not be measured, then what is fine.
        component Line: Item {
          id: line
          required property var modelData
          width: content.inner
          height: lineName.height
          Plain {
            id: lineIcon
            anchors.verticalCenter: parent.verticalCenter
            font.pixelSize: Style.font.icon
            color: root.levelColor(line.modelData.level)
            text: root.levelIcon(line.modelData.level)
          }
          Plain {
            id: lineName
            x: lineIcon.width + Style.space(8)
            text: line.modelData.name
          }
          Row {
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: Style.space(12)
            Plain { color: NetCommons.Color.muted; text: line.modelData.brief }
            Link {
              visible: line.modelData.id === "dns" && root.dnsChoice === "encrypted"
              text: strings.t("link.dnsUndo")
              onActivated: root.choose("dns", "auto")
            }
          }
        }

        PanelSectionHeader {
          visible: root.unmeasured.length > 0
          text: strings.t("section.unmeasured").arg(NetCommons.I18n.formatNumber(root.unmeasured.length))
        }
        Column {
          visible: root.unmeasured.length > 0
          width: content.inner
          spacing: Style.space(5)
          Repeater { model: root.unmeasured; Line {} }
        }

        PanelSectionHeader {
          visible: root.settled.length > 0
          text: strings.t("section.settled").arg(NetCommons.I18n.formatNumber(root.settled.length))
        }
        Column {
          visible: root.settled.length > 0
          width: content.inner
          spacing: Style.space(5)
          Repeater { model: root.settled; Line {} }
        }

        // The most recent change
        Column {
          visible: root.lastChange !== null
          width: content.inner
          spacing: Style.space(2)
          PanelSeparator { width: parent.width }
          Item { width: 1; height: Style.space(6) }
          Plain {
            width: parent.width
            font.pixelSize: Style.font.caption
            color: NetCommons.Color.muted
            text: root.lastChange ? root.lastChange.title : ""
          }
          Repeater {
            model: root.lastChange ? root.lastChange.lines : []
            Plain {
              required property var modelData
              width: content.inner
              font.pixelSize: Style.font.caption
              text: modelData
            }
          }
        }

        PanelSeparator { width: content.inner }

        Row {
          spacing: Style.space(8)
          Button {
            text: root.scanning ? strings.t("button.scanning") : strings.t("button.scan")
            bordered: true
            enabled: !root.scanning
            onClicked: root.scan()
          }
          Button {
            visible: root.report !== null
            text: root.agentName !== ""
              ? strings.t("button.ask").arg(root.agentName.charAt(0).toUpperCase() + root.agentName.slice(1))
              : strings.t("button.chooseAgent")
            tooltipText: root.agentName !== "" ? strings.t("button.askTip") : strings.t("button.chooseTip")
            bordered: true
            onClicked: root.explain("all")
          }
        }

        PanelSeparator { width: content.inner }

        // Background checks, off until the owner asks for them.
        Row {
          width: content.inner
          spacing: Style.space(12)
          Column {
            width: parent.width - watchSwitch.width - parent.spacing
            anchors.verticalCenter: parent.verticalCenter
            Plain { width: parent.width; text: strings.t("watch.label") }
            Plain {
              width: parent.width
              font.pixelSize: Style.font.caption
              color: NetCommons.Color.muted
              text: strings.tn("watch.detail", root.watchMinutes).arg(NetCommons.I18n.formatNumber(root.watchMinutes))
            }
          }
          ToggleSwitch {
            id: watchSwitch
            anchors.verticalCenter: parent.verticalCenter
            checked: root.watching
            busy: setProc.running
            onToggled: root.choose("watch", root.watching ? "off" : "on")
          }
        }
      }

      }

      // "How to read this": a small card floating over the checks, opened by
      // the (i) button. A click anywhere outside it, or Esc, closes it.
      MouseArea {
        anchors.fill: parent
        visible: root.showInfo
        z: 9
        onClicked: root.showInfo = false
      }
      Rectangle {
        id: infoCard
        readonly property real pad: Style.space(12)
        visible: root.showInfo
        z: 10
        x: content.leftPadding
        y: Math.max(pad, content.topPadding + scoreRow.height + Style.space(6) - flick.contentY)
        width: content.inner
        height: infoColumn.implicitHeight + pad * 2
        // Opaque even when the theme's popups are see-through, so the checks
        // underneath do not show through the text.
        color: Qt.rgba(NetCommons.Color.popups.background.r, NetCommons.Color.popups.background.g, NetCommons.Color.popups.background.b, 1)
        border.color: NetCommons.Color.popups.border
        border.width: 1
        radius: Style.cornerRadius

        // Clicks on the card itself do nothing, and do not close it.
        MouseArea { anchors.fill: parent }

        Column {
          id: infoColumn
          x: infoCard.pad
          y: infoCard.pad
          width: infoCard.width - infoCard.pad * 2
          spacing: Style.space(6)

          PanelSectionHeader { text: strings.t("info.header") }
          Plain { width: parent.width; text: strings.t("info.intro") }
          Repeater {
            model: ["green", "yellow", "orange", "red"]
            Row {
              id: band
              required property string modelData
              width: infoColumn.width
              spacing: Style.space(8)
              Plain { id: dot; color: root[band.modelData]; text: "●" }
              Plain {
                width: band.width - dot.width - band.spacing
                text: strings.t("info.band")
                  .arg(strings.t("verdict." + band.modelData))
                  .arg(strings.t("info." + band.modelData + ".range"))
                  .arg(strings.t("info." + band.modelData + ".note"))
              }
            }
          }
          Plain {
            width: parent.width
            color: NetCommons.Color.muted
            font.pixelSize: Style.font.caption
            text: strings.t("info.caps") + "\n" + strings.t("info.reachable") + "\n" + strings.t("info.unknown")
          }
        }
      }
    }
  }
}
