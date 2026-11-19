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
// when the owner switches on "Alert me when something changes". Otherwise it
// starts no process at all while idle: it watches its report and settings
// files and rereads them when they change.
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
  // A failed scan stays on show until a scan succeeds; rereading the saved
  // report must not wipe it, or an old score would pass for a current one.
  property string scanError: ""
  property string readError: ""
  // A setting the helper refused ("scan this network first"); shown until
  // the owner changes a setting again.
  property string settingError: ""
  readonly property string error: settingError !== "" ? settingError : scanError !== "" ? scanError : readError
  readonly property bool scanning: scanProc.running || autoProc.running
  // A scan asked for while the background check is running; started when it ends.
  property bool scanWanted: false
  // Whether the "how to read this" notes are showing in the popup.
  property bool showInfo: false

  // The score as read from disk, kept only when its numbers are numbers.
  readonly property var score: {
    const raw = report && report.score ? report.score : null
    if (!raw || typeof raw !== "object") return null
    const within = v => typeof v === "number" && isFinite(v) ? Math.max(0, Math.min(100, Math.round(v))) : null
    const coverage = within(raw.coverage)
    return coverage === null ? null : { provisional: within(raw.provisional), coverage: coverage }
  }
  readonly property bool hasScore: score !== null && score.provisional !== null
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
    const lines = c.items.slice(0, 3).filter(item => item && typeof item === "object").map(item => {
      const key = word(item.key), from = word(item.from), to = word(item.to)
      return strings.t("change.item").arg(tr("fact." + key, key)).arg(tr("value." + from, from)).arg(tr("value." + to, to))
    })
    return { title: strings.t("change.line").arg(when), lines: lines }
  }

  // `fromScan` is true for the answer to a scan, false for a plain reread.
  function take(text, fromScan) {
    let parsed = null
    try { if (String(text).length <= 262144) parsed = JSON.parse(text) } catch (e) {}
    const failed = !parsed || typeof parsed !== "object" || parsed.error !== undefined
    if (fromScan) {
      // An answer with an "error" key is a failure even when the text is empty.
      root.scanError = !failed ? "" : (parsed && clip(parsed.error, 200)) || strings.t("error.scanFailed")
      if (failed) return
    } else {
      root.readError = failed ? strings.t("error.unreadable") : ""
      if (failed) return
    }
    // A missing report ("{}") is "no scan yet"; it never replaces a report on
    // show after a failed scan.
    if (parsed.findings) root.report = parsed
    else if (!fromScan && root.scanError === "") root.report = null
  }

  // The helper's answer to a change of setting. The values themselves arrive
  // through the settings file; only a refusal needs showing.
  function takeSettings(text) {
    try {
      const s = JSON.parse(text)
      root.settingError = s && s.error ? clip(s.error, 200) : ""
    } catch (e) {}
    settingsFile.refresh()
  }

  // The settings file: one key=value per line, written by the helper.
  function readSettings(text) {
    const values = {}
    for (const line of String(text).slice(0, 2000).split("\n")) {
      const m = /^([a-z]+)=([a-z0-9]*)$/.exec(line.trim())
      if (m) values[m[1]] = m[2]
    }
    root.dnsChoice = values.dns === "encrypted" ? "encrypted" : "auto"
    root.watching = values.watch === "on"
  }

  // Opens the Omarchy default coding agent in a terminal, on the saved report.
  // `what` is a check id from checkOrder, or "all".
  function explain(what) {
    Quickshell.execDetached([root.helperPath, "explain", what, root.router])
    root.close()
  }

  function scan() {
    if (scanProc.running) return
    root.settingError = ""
    // The background check holds the scan lock; queue behind it.
    if (autoProc.running) { root.scanWanted = true; return }
    scanProc.running = true
  }

  // Changes one of the owner's choices. Nothing here scans: a DNS choice
  // re-scores the saved report, which the file watch then shows.
  function choose(name, value) {
    if (setProc.running) return
    root.settingError = ""
    setProc.command = [root.helperPath, "set", name, value]
    setProc.running = true
  }

  // The network this computer is on now, as a scrambled id; asked when the
  // popup opens, and answered from this computer's own tables, without
  // sending anything. The saved report may be from somewhere else.
  property string currentNetwork: ""
  readonly property bool otherNetwork: currentNetwork !== "" && report !== null
    && typeof report.networkId === "string" && report.networkId !== "" && report.networkId !== currentNetwork

  function metaLine() {
    if (!report) return strings.t("meta.none")
    const parts = []
    if (score) parts.push(strings.t("meta.coverage").arg(NetCommons.I18n.formatNumber(Math.round(score.coverage))))
    const when = formatWhen(report.generatedAt)
    if (when !== "") parts.push(strings.t("meta.scanned").arg(when))
    return parts.join("\n")
  }

  Process {
    id: scanProc
    command: [root.helperPath, "scan"]
    stdout: StdioCollector { waitForEnd: true; onStreamFinished: root.take(text, true) }
    onRunningChanged: if (!running) reportFile.refresh()
  }

  // The report, the settings and Omarchy's default agent, read straight from
  // their files and reread when a file changes. No process is started for any
  // of this, so an idle bar costs nothing.
  readonly property string homeDir: Quickshell.env("HOME") || ""
  readonly property string stateDir: (Quickshell.env("XDG_STATE_HOME") || homeDir + "/.local/state") + "/netaudit"
  readonly property string configDir: (Quickshell.env("XDG_CONFIG_HOME") || homeDir + "/.config")

  // A watch can only be attached to a file that exists, and on a new install
  // none of these files does. So each file is read by a view that is built
  // afresh, exactly as at start-up, once its file may have appeared: after a
  // scan or a change of setting, and whenever the popup opens.
  component Watched: Item {
    id: watched
    property string file: ""
    property bool missing: false
    signal loaded(string content)
    signal absent()
    visible: false
    function refresh() {
      if (!missing && viewLoader.item) { viewLoader.item.reload(); return }
      viewLoader.active = false
      Qt.callLater(() => { viewLoader.active = true })
    }
    Loader {
      id: viewLoader
      active: true
      sourceComponent: FileView {
        path: watched.file
        watchChanges: true
        printErrors: false
        onFileChanged: reload()
        onLoaded: { watched.missing = false; watched.loaded(text()) }
        onLoadFailed: { watched.missing = true; watched.absent() }
      }
    }
  }

  Watched {
    id: reportFile
    file: root.stateDir + "/sanitized-report.json"
    onLoaded: content => root.take(content, false)
    // No report file is "no scan yet", not an error.
    onAbsent: root.take("{}", false)
  }
  Watched {
    id: settingsFile
    file: root.configDir + "/netaudit/settings"
    onLoaded: content => root.readSettings(content)
    onAbsent: root.readSettings("")
  }
  Watched {
    id: agentFile
    file: root.configDir + "/omarchy/defaults/agent"
    onLoaded: content => root.agentName = root.word(content.trim())
    onAbsent: root.agentName = ""
  }

  // The background check. The helper does nothing unless watching is on and
  // the report is older than the watch interval, so several bars do not scan
  // several times.
  Process {
    id: autoProc
    command: [root.helperPath, "scan", "auto"]
    // Its answer is the saved report either way, so it is read as a reread:
    // a background failure must not put an error in front of the owner.
    stdout: StdioCollector { waitForEnd: true }
    onRunningChanged: {
      if (running) return
      reportFile.refresh()
      if (root.scanWanted) { root.scanWanted = false; root.scan() }
    }
  }

  Process {
    id: netProc
    command: [root.helperPath, "network"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try { root.currentNetwork = root.word(JSON.parse(text).network) } catch (e) { root.currentNetwork = "" }
      }
    }
  }

  Process {
    id: setProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        root.takeSettings(text)
        reportFile.refresh()
      }
    }
  }

  // When the background check last ran, so that on a network where it does
  // nothing (anywhere but home) it is not started again every minute.
  property real autoTriedAt: 0

  // While alerts are on, look once a minute whether a scan is due. That look
  // is a comparison of two times; a process is started only when the report
  // is older than the interval, which is once per interval.
  Timer {
    interval: 60000
    running: root.watching
    repeat: true
    onTriggered: {
      const every = root.watchMinutes * 60000
      const scanned = root.report ? Date.parse(root.report.generatedAt) : 0
      const now = Date.now()
      if (now - (scanned || 0) < every || now - root.autoTriedAt < every) return
      if (scanProc.running || autoProc.running) return
      root.autoTriedAt = now
      autoProc.running = true
    }
  }
  // Opening the popup rereads everything, in case a change was missed.
  onOpenedChanged: {
    if (!opened) { root.showInfo = false; root.settingError = ""; return }
    reportFile.refresh(); settingsFile.refresh(); agentFile.refresh()
    if (!netProc.running) netProc.running = true
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
          visible: root.otherNetwork
          width: content.inner
          color: root.yellow
          text: strings.t("note.otherNetwork")
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
                Plain {
                  id: problemName
                  width: Math.max(0, parent.width - problemSide.width - Style.space(10))
                  wrapMode: Text.NoWrap
                  elide: Text.ElideRight
                  font.bold: true
                  text: problem.modelData.name
                }
                Row {
                  id: problemSide
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
                // The fix is the line people act on. Some themes make their
                // muted colour very faint, so it stays in the text colour.
                opacity: 0.82
                text: problem.modelData.fix
              }
              // DNS is measured on this computer. A router that encrypts DNS
              // for the whole home is something only the owner knows.
              Link {
                // Only for the network the report is of: a declaration made
                // while somewhere else would be about the wrong router.
                visible: problem.modelData.id === "dns" && !root.otherNetwork
                  && (problem.modelData.state === "plaintext-measured" || problem.modelData.state === "opportunistic")
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
            width: Math.max(0, line.width - x - lineSide.width - Style.space(10))
            wrapMode: Text.NoWrap
            elide: Text.ElideRight
            text: line.modelData.name
          }
          Row {
            id: lineSide
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
