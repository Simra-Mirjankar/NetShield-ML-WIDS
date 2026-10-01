import { useEffect, useState } from 'react'
import './App.css'

const sidebarItems = [
  'Dashboard',
  'WiFi Scan',
  'Live Monitor',
  'ML Detection',
  'Incidents',
  'Reports',
  'Settings',
]


const API_BASE_URL = 'http://127.0.0.1:5000/api'
const ACTIVE_SCANNER_STATES = ['starting', 'running', 'stopping']
const ACTIVE_CAPTURE_STATES = ['starting', 'running', 'stopping']

const getValue = (source, keys) => {
  for (const key of keys) {
    if (source?.[key] !== undefined && source[key] !== null && source[key] !== '') {
      return source[key]
    }
  }

  return null
}

const normalizeList = (payload, key) => {
  if (Array.isArray(payload)) {
    return payload
  }

  if (Array.isArray(payload?.[key])) {
    return payload[key]
  }

  if (Array.isArray(payload?.data)) {
    return payload.data
  }

  return []
}

const formatValue = (value) => value ?? 'Not reported'

const formatWithUnit = (value, unit) => (value === undefined || value === null ? 'Not reported' : `${value} ${unit}`)

const formatProbability = (value) => {
  if (value === undefined || value === null || Number.isNaN(Number(value))) {
    return 'Not reported'
  }

  return `${(Number(value) * 100).toFixed(1)}%`
}

const formatDateTime = (value) => {
  if (!value) {
    return 'Not reported'
  }

  try {
    const date = new Date(value)
    if (Number.isNaN(date.getTime())) {
      return String(value)
    }

    return date.toLocaleString()
  } catch {
    return String(value)
  }
}

const getSeverityBadgeClass = (severity) => {
  const normalized = String(severity ?? '').toLowerCase()
  if (normalized === 'high') {
    return 'badge badge-severity-high'
  }
  if (normalized === 'medium') {
    return 'badge badge-severity-medium'
  }
  if (normalized === 'low') {
    return 'badge badge-severity-low'
  }

  return 'badge badge-default'
}

const getStatusBadgeClass = (status) => {
  const normalized = String(status ?? '').toLowerCase()
  if (normalized === 'new') {
    return 'badge badge-status-new'
  }
  if (normalized === 'resolved') {
    return 'badge badge-status-resolved'
  }

  return 'badge badge-default'
}

const normalizeScannerStatus = (payload) => payload?.scanner ?? payload?.status ?? payload ?? {}

const normalizeCaptureStatus = (payload) => payload?.capture ?? payload?.status ?? payload ?? {}

const getInterfaceName = (source) => getValue(source, ['name', 'interface', 'interface_name'])

const getScannerState = (scannerStatus) =>
  String(getValue(scannerStatus, ['state', 'scanner_state', 'status']) ?? 'stopped').toLowerCase()

const getCaptureState = (captureStatus) =>
  String(getValue(captureStatus, ['state', 'capture_state', 'status']) ?? 'stopped').toLowerCase()

const normalizeCounts = (counts) =>
  counts && typeof counts === 'object' && !Array.isArray(counts) ? counts : {}

function App() {
  const [activeView, setActiveView] = useState('Dashboard')
  const [interfaces, setInterfaces] = useState([])
  const [adapterState, setAdapterState] = useState(null)
  const [networks, setNetworks] = useState([])
  const [scannerStatus, setScannerStatus] = useState({})
  const [captureStatus, setCaptureStatus] = useState({})
  const [packets, setPackets] = useState([])
  const [selectedInterfaceName, setSelectedInterfaceName] = useState('')
  const [selectedCaptureInterfaceName, setSelectedCaptureInterfaceName] = useState('')
  const [wifiScanLoading, setWifiScanLoading] = useState(false)
  const [wifiScanError, setWifiScanError] = useState('')
  const [scannerActionLoading, setScannerActionLoading] = useState(false)
  const [liveMonitorLoading, setLiveMonitorLoading] = useState(false)
  const [liveMonitorError, setLiveMonitorError] = useState('')
  const [captureActionLoading, setCaptureActionLoading] = useState(false)
  const [mlLiveStatus, setMlLiveStatus] = useState(null)
  const [mlDetectionLoading, setMlDetectionLoading] = useState(false)
  const [mlDetectionError, setMlDetectionError] = useState('')
  const [incidents, setIncidents] = useState([])
  const [incidentsLoading, setIncidentsLoading] = useState(false)
  const [incidentsError, setIncidentsError] = useState('')
  const [reportIncidents, setReportIncidents] = useState([])
  const [reportsLoading, setReportsLoading] = useState(false)
  const [reportsError, setReportsError] = useState('')

  const fetchJson = async (path, options = {}) => {
    const response = await fetch(`${API_BASE_URL}${path}`, options)

    if (!response.ok) {
      throw new Error(`Request failed: ${path}`)
    }

    return response.json()
  }

  const updateSelectedInterface = (availableInterfaces) => {
    setSelectedInterfaceName((currentInterfaceName) => {
      if (availableInterfaces.some((adapter) => getInterfaceName(adapter) === currentInterfaceName)) {
        return currentInterfaceName
      }

      return getInterfaceName(availableInterfaces[0]) ?? ''
    })

    setSelectedCaptureInterfaceName((currentInterfaceName) => {
      if (availableInterfaces.some((adapter) => getInterfaceName(adapter) === currentInterfaceName)) {
        return currentInterfaceName
      }

      return getInterfaceName(availableInterfaces[0]) ?? ''
    })
  }

  const loadInterfaces = async (signal) => {
    const interfacesPayload = await fetchJson('/interfaces', { signal })
    const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')

    setAdapterState(getValue(interfacesPayload, ['state']))
    setInterfaces(availableInterfaces)
    updateSelectedInterface(availableInterfaces)
  }

  const loadNetworks = async (signal) => {
    const networksPayload = await fetchJson('/networks', { signal })
    setNetworks(normalizeList(networksPayload, 'networks'))
  }

  const loadScannerStatus = async (signal) => {
    const statusPayload = await fetchJson('/scanner/status', { signal })
    const normalizedStatus = normalizeScannerStatus(statusPayload)

    setScannerStatus(normalizedStatus)

    return normalizedStatus
  }

  const loadCaptureStatus = async (signal) => {
    const statusPayload = await fetchJson('/capture/status', { signal })
    const normalizedStatus = normalizeCaptureStatus(statusPayload)

    setCaptureStatus(normalizedStatus)

    return normalizedStatus
  }

  const loadPackets = async (signal) => {
    const packetsPayload = await fetchJson('/packets?limit=20', { signal })
    setPackets(normalizeList(packetsPayload, 'packets'))
  }

  useEffect(() => {
    if (activeView !== 'Dashboard') {
      return
    }

    const controller = new AbortController()

    const loadDashboardData = async () => {
      try {
        await Promise.all([
          loadInterfaces(controller.signal),
          loadNetworks(controller.signal),
          loadCaptureStatus(controller.signal),
          loadPackets(controller.signal),
        ])
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }
      }
    }

    loadDashboardData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'WiFi Scan') {
      return
    }

    const controller = new AbortController()

    const loadWifiScanData = async () => {
      setWifiScanLoading(true)
      setWifiScanError('')

      try {
        const [interfacesPayload, networksPayload, statusPayload, capturePayload] = await Promise.all([
          fetchJson('/interfaces', { signal: controller.signal }),
          fetchJson('/networks', { signal: controller.signal }),
          fetchJson('/scanner/status', { signal: controller.signal }),
          fetchJson('/capture/status', { signal: controller.signal }),
        ])

        const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')

        setInterfaces(availableInterfaces)
        setAdapterState(getValue(interfacesPayload, ['state']))
        setNetworks(normalizeList(networksPayload, 'networks'))
        setScannerStatus(normalizeScannerStatus(statusPayload))
        setCaptureStatus(normalizeCaptureStatus(capturePayload))
        updateSelectedInterface(availableInterfaces)
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setInterfaces([])
        setNetworks([])
        setWifiScanError(
          'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setWifiScanLoading(false)
        }
      }
    }

    loadWifiScanData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Live Monitor') {
      return
    }

    const controller = new AbortController()

    const loadLiveMonitorData = async () => {
      setLiveMonitorLoading(true)
      setLiveMonitorError('')

      try {
        const [interfacesPayload, scannerPayload, capturePayload] = await Promise.all([
          fetchJson('/interfaces', { signal: controller.signal }),
          fetchJson('/scanner/status', { signal: controller.signal }),
          fetchJson('/capture/status', { signal: controller.signal }),
        ])
        const availableInterfaces = normalizeList(interfacesPayload, 'interfaces')
        const normalizedCaptureStatus = normalizeCaptureStatus(capturePayload)

        setInterfaces(availableInterfaces)
        setAdapterState(getValue(interfacesPayload, ['state']))
        setScannerStatus(normalizeScannerStatus(scannerPayload))
        setCaptureStatus(normalizedCaptureStatus)
        updateSelectedInterface(availableInterfaces)

        if (ACTIVE_CAPTURE_STATES.includes(getCaptureState(normalizedCaptureStatus))) {
          await loadPackets(controller.signal)
        }
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setPackets([])
        setLiveMonitorError(
          'Unable to connect to the NetShield capture backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setLiveMonitorLoading(false)
        }
      }
    }

    loadLiveMonitorData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Live Monitor') {
      return
    }

    let activePollController = null

    const pollLiveMonitor = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      Promise.all([
        loadCaptureStatus(controller.signal),
        loadScannerStatus(controller.signal),
        loadInterfaces(controller.signal),
      ])
        .then(([latestCaptureStatus]) => {
          if (ACTIVE_CAPTURE_STATES.includes(getCaptureState(latestCaptureStatus))) {
            return loadPackets(controller.signal)
          }

          return null
        })
        .catch((error) => {
          if (error.name !== 'AbortError') {
            setLiveMonitorError(
              'Unable to refresh capture data from http://127.0.0.1:5000. Check that the Flask backend is running.',
            )
          }
        })
    }

    const intervalId = setInterval(pollLiveMonitor, 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'WiFi Scan') {
      return
    }

    let activePollController = null

    const pollWifiScan = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      Promise.all([
        loadScannerStatus(controller.signal),
        loadInterfaces(controller.signal),
        loadCaptureStatus(controller.signal),
      ])
        .then(([latestScannerStatus]) => {
          if (ACTIVE_SCANNER_STATES.includes(getScannerState(latestScannerStatus))) {
            return loadNetworks(controller.signal)
          }

          return null
        })
        .catch((error) => {
          if (error.name !== 'AbortError') {
            setWifiScanError(
              'Unable to refresh scanner data from http://127.0.0.1:5000. Check that the Flask backend is running.',
            )
          }
        })

    }

    const intervalId = setInterval(pollWifiScan, 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'ML Detection' && activeView !== 'Dashboard') {
      return
    }

    const controller = new AbortController()

    const loadMlDetectionData = async () => {
      setMlDetectionLoading(true)
      setMlDetectionError('')

      try {
        const payload = await fetchJson('/ml/live-status', { signal: controller.signal })
        setMlLiveStatus(payload)
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setMlLiveStatus(null)
        setMlDetectionError(
          'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setMlDetectionLoading(false)
        }
      }
    }

    loadMlDetectionData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'ML Detection' && activeView !== 'Dashboard') {
      return
    }

    let activePollController = null

    const pollMlDetection = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      fetchJson('/ml/live-status', { signal: controller.signal })
        .then((payload) => {
          setMlDetectionError('')
          setMlLiveStatus(payload)
        })
        .catch((error) => {
          if (error.name !== 'AbortError') {
            setMlDetectionError(
              'Unable to refresh ML inference data from http://127.0.0.1:5000. Check that the Flask backend is running.',
            )
          }
        })
    }

    const intervalId = setInterval(pollMlDetection, 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Incidents' && activeView !== 'Dashboard') {
      return
    }

    const controller = new AbortController()

    const loadIncidentsData = async () => {
      setIncidentsLoading(true)
      setIncidentsError('')

      try {
        const payload = await fetchJson('/incidents', { signal: controller.signal })
        setIncidents(normalizeList(payload, 'incidents'))
      } catch (error) {
        if (error.name === 'AbortError') {
          return
        }

        setIncidents([])
        setIncidentsError(
          'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
        )
      } finally {
        if (!controller.signal.aborted) {
          setIncidentsLoading(false)
        }
      }
    }

    loadIncidentsData()

    return () => controller.abort()
  }, [activeView])

  useEffect(() => {
    if (activeView !== 'Incidents' && activeView !== 'Dashboard') {
      return
    }

    let activePollController = null

    const pollIncidents = () => {
      activePollController?.abort()
      activePollController = new AbortController()
      const controller = activePollController

      fetchJson('/incidents', { signal: controller.signal })
        .then((payload) => {
          setIncidents(normalizeList(payload, 'incidents'))
        })
        .catch(() => {})
    }

    const intervalId = setInterval(pollIncidents, 2000)

    return () => {
      activePollController?.abort()
      clearInterval(intervalId)
    }
  }, [activeView])

  const loadReportsData = async (signal) => {
    setReportsLoading(true)
    setReportsError('')

    try {
      const payload = await fetchJson('/incidents', { signal })
      setReportIncidents(normalizeList(payload, 'incidents'))
    } catch (error) {
      if (error.name === 'AbortError') {
        return
      }

      setReportIncidents([])
      setReportsError(
        'Unable to connect to the NetShield backend at http://127.0.0.1:5000. Start the Flask server and try again.',
      )
    } finally {
      if (!signal?.aborted) {
        setReportsLoading(false)
      }
    }
  }

  useEffect(() => {
    if (activeView !== 'Reports') {
      return
    }

    const controller = new AbortController()
    loadReportsData(controller.signal)

    return () => controller.abort()
  }, [activeView])

  const wirelessAdapter =
    interfaces.find((adapter) => getInterfaceName(adapter) === selectedInterfaceName) ?? interfaces[0] ?? null
  const selectedInterface = getInterfaceName(wirelessAdapter)
  const scannerState = getScannerState(scannerStatus)
  const scannerProgress = scannerStatus.progress ?? {}
  const isScannerActive = ACTIVE_SCANNER_STATES.includes(scannerState)
  const isScannerStarting = scannerState === 'starting'
  const isScannerRunning = scannerState === 'running'
  const isScannerStopping = scannerState === 'stopping'
  const selectableInterfaces = interfaces.filter((adapter) => getInterfaceName(adapter))
  const captureAdapter =
    interfaces.find((adapter) => getInterfaceName(adapter) === selectedCaptureInterfaceName) ??
    interfaces[0] ??
    null
  const selectedCaptureInterface = getInterfaceName(captureAdapter)
  const captureState = getCaptureState(captureStatus)
  const isCaptureActive = ACTIVE_CAPTURE_STATES.includes(captureState)
  const isCaptureStarting = captureState === 'starting'
  const isCaptureRunning = captureState === 'running'
  const isCaptureStopping = captureState === 'stopping'
  const captureProgress = captureStatus.progress ?? {}
  const packetTypeCounts = normalizeCounts(captureProgress.packet_type_counts)
  const startScanDisabled =
    !selectedInterface ||
    scannerActionLoading ||
    isCaptureActive ||
    isScannerStarting ||
    isScannerRunning ||
    isScannerStopping
  const stopScanDisabled = !isScannerActive || scannerActionLoading
  const startCaptureDisabled =
    !selectedCaptureInterface ||
    isScannerActive ||
    captureActionLoading ||
    isCaptureStarting ||
    isCaptureRunning ||
    isCaptureStopping
  const stopCaptureDisabled = !isCaptureActive || captureActionLoading
  const totalIncidents = incidents.length
  const newIncidents = incidents.filter(
    (incident) => String(incident?.status ?? '').toLowerCase() === 'new',
  ).length
  const highSeverityIncidents = incidents.filter(
    (incident) => String(incident?.severity ?? '').toLowerCase() === 'high',
  ).length

  const dashboardCards = [
    ['Security Score', '--'],
    ['Active Threats', totalIncidents],
    ['Networks Found', networks.length],
    ['Packets Analyzed', getValue(captureProgress, ['packet_count']) ?? packets.length],
  ]

  const monitoringStatus =
    getValue(captureStatus, ['state', 'capture_state', 'status']) ??
    (captureState === 'stopped' ? 'Stopped' : captureState)
  const monitoringNetwork =
    getValue(captureProgress, ['network', 'ssid']) ?? 'None'
  const monitoringInterface =
    getValue(captureStatus, ['interface', 'interface_name']) ??
    getValue(captureProgress, ['interface']) ??
    (selectedCaptureInterface || 'Not Selected')

  const reportTotalIncidents = reportIncidents.length
  const reportHighSeverity = reportIncidents.filter(
    (incident) => String(incident?.severity ?? '').toLowerCase() === 'high',
  ).length
  const reportTotalPackets = reportIncidents.reduce((sum, inc) => {
    const val = Number(inc?.total_packets)
    return Number.isFinite(val) ? sum + val : sum
  }, 0)
  const reportAvgAttackProb =
    reportIncidents.length > 0
      ? reportIncidents.reduce((sum, inc) => {
          const val = Number(inc?.attack_probability)
          return Number.isFinite(val) ? sum + val : sum
        }, 0) / reportIncidents.length
      : null

  const attackCountsByLabel = reportIncidents.reduce((acc, inc) => {
    const label = String(inc?.label ?? (inc?.prediction !== undefined ? `Class ${inc.prediction}` : 'Unknown'))
    acc[label] = (acc[label] || 0) + 1
    return acc
  }, {})

  const handleRefreshReports = () => {
    loadReportsData()
  }

  const handleExportCsv = () => {
    if (!reportIncidents || reportIncidents.length === 0) {
      return
    }

    const headers = [
      'ID',
      'Created At',
      'Label',
      'Attack Probability',
      'Normal Probability',
      'Total Packets',
      'Window Start',
      'Window End',
      'Feature Count',
      'Severity',
      'Status',
    ]

    const formatCsvField = (val) => {
      if (val === undefined || val === null) {
        return ''
      }
      const str = String(val)
      if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
        return `"${str.replace(/"/g, '""')}"`
      }
      return str
    }

    const rows = reportIncidents.map((incident) => [
      formatCsvField(incident.id),
      formatCsvField(incident.created_at),
      formatCsvField(incident.label ?? (incident.prediction !== undefined ? `Class ${incident.prediction}` : '')),
      formatCsvField(incident.attack_probability),
      formatCsvField(incident.normal_probability),
      formatCsvField(incident.total_packets),
      formatCsvField(incident.window_start),
      formatCsvField(incident.window_end),
      formatCsvField(incident.feature_count),
      formatCsvField(incident.severity),
      formatCsvField(incident.status),
    ])

    const csvContent = [headers.join(','), ...rows.map((row) => row.join(','))].join('\r\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.setAttribute('download', `netshield_incident_report_${new Date().toISOString().slice(0, 10)}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    URL.revokeObjectURL(url)
  }

  const handleStartScan = async () => {
    if (startScanDisabled) {
      return
    }

    setScannerActionLoading(true)
    setWifiScanError('')

    try {
      await fetchJson('/scanner/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedInterface }),
      })
      await loadScannerStatus()
      await loadNetworks()
    } catch {
      setWifiScanError('Unable to start the scanner. Check the selected interface and Flask backend logs.')
    } finally {
      setScannerActionLoading(false)
    }
  }

  const handleStopScan = async () => {
    if (stopScanDisabled) {
      return
    }

    setScannerActionLoading(true)
    setWifiScanError('')

    try {
      await fetchJson('/scanner/stop', { method: 'POST' })
      await Promise.all([loadScannerStatus(), loadNetworks()])
      await loadInterfaces()
    } catch {
      setWifiScanError('Unable to stop the scanner. Check that the Flask backend is running.')
    } finally {
      setScannerActionLoading(false)
    }
  }

  const handleStartCapture = async () => {
    if (startCaptureDisabled) {
      return
    }

    setCaptureActionLoading(true)
    setLiveMonitorError('')

    try {
      await fetchJson('/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedCaptureInterface }),
      })
      await loadCaptureStatus()
      await loadPackets()
    } catch {
      setLiveMonitorError('Unable to start packet capture. Check the selected interface and Flask backend logs.')
    } finally {
      setCaptureActionLoading(false)
    }
  }

  const handleStopCapture = async () => {
    if (stopCaptureDisabled) {
      return
    }

    setCaptureActionLoading(true)
    setLiveMonitorError('')

    try {
      await fetchJson('/capture/stop', { method: 'POST' })
      await Promise.all([loadCaptureStatus(), loadPackets(), loadInterfaces()])
    } catch {
      setLiveMonitorError('Unable to stop packet capture. Check that the Flask backend is running.')
    } finally {
      setCaptureActionLoading(false)
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar" aria-label="Primary navigation">
        <div className="brand">
          <span className="brand-mark">NS</span>
          <div>
            <p className="brand-name">NetShield</p>
            <p className="brand-subtitle">WiFi IDS</p>
          </div>
        </div>

        <nav className="nav-list">
          {sidebarItems.map((item) => (
            <button
              className={item === activeView ? 'nav-item active' : 'nav-item'}
              key={item}
              onClick={() => setActiveView(item)}
              type="button"
            >
              {item}
            </button>
          ))}
        </nav>
      </aside>

      <div className="workspace">
        <header className="top-header">
          <div>
            <p className="eyebrow">ML-Based WiFi Intrusion Detection</p>
            <h1>NetShield</h1>
            <p className="page-title">{activeView}</p>
          </div>
          <div className="header-status">
            <span className="status-dot"></span>
            Monitoring not started
          </div>
        </header>

        <main className="main-content">
          {activeView === 'Dashboard' ? (
            <section className="dashboard-view" aria-label="Dashboard overview">
              <div className="metric-grid">
                {dashboardCards.map(([label, value]) => (
                  <article className="metric-card" key={label}>
                    <p>{label}</p>
                    <strong>{value}</strong>
                  </article>
                ))}
              </div>

              <div className="panel-grid">
                <section className="panel">
                  <h2>Current Monitoring</h2>
                  <dl className="status-list">
                    <div>
                      <dt>Status</dt>
                      <dd>{formatValue(monitoringStatus)}</dd>
                    </div>
                    <div>
                      <dt>Network</dt>
                      <dd>{formatValue(monitoringNetwork)}</dd>
                    </div>
                    <div>
                      <dt>Interface</dt>
                      <dd>{formatValue(monitoringInterface)}</dd>
                    </div>
                  </dl>
                </section>

                <section className="panel">
                  <h2>Latest Detection</h2>
                  {mlLiveStatus && mlLiveStatus.status !== 'no_inference' && mlLiveStatus.prediction !== undefined ? (
                    <dl className="status-list">
                      <div>
                        <dt>Label</dt>
                        <dd>{formatValue(mlLiveStatus.label)}</dd>
                      </div>
                      <div>
                        <dt>Prediction</dt>
                        <dd>{formatValue(mlLiveStatus.prediction)}</dd>
                      </div>
                      <div>
                        <dt>Attack Probability</dt>
                        <dd>{formatProbability(mlLiveStatus.attack_probability)}</dd>
                      </div>
                      <div>
                        <dt>Normal Probability</dt>
                        <dd>{formatProbability(mlLiveStatus.normal_probability)}</dd>
                      </div>
                      <div>
                        <dt>Total Packets</dt>
                        <dd>{formatValue(mlLiveStatus.total_packets)}</dd>
                      </div>
                      <div>
                        <dt>Feature Count</dt>
                        <dd>{formatValue(mlLiveStatus.feature_count)}</dd>
                      </div>
                    </dl>
                  ) : (
                    <p className="empty-state">No traffic has been analyzed yet.</p>
                  )}
                </section>
              </div>
            </section>
          ) : activeView === 'WiFi Scan' ? (
            <section className="wifi-scan-view" aria-label="WiFi scan">
              {wifiScanError ? <p className="error-banner">{wifiScanError}</p> : null}

              <section className="panel adapter-panel">
                <div className="panel-header">
                  <h2>Wireless Adapter</h2>
                  <div className="scan-actions">
                    <button
                      className="scan-button primary"
                      disabled={startScanDisabled}
                      onClick={handleStartScan}
                      type="button"
                    >
                      Start Scan
                    </button>
                    <button
                      className="scan-button"
                      disabled={stopScanDisabled}
                      onClick={handleStopScan}
                      type="button"
                    >
                      Stop Scan
                    </button>
                  </div>
                </div>
                {wifiScanLoading ? (
                  <p className="muted-text">Loading adapter details...</p>
                ) : wirelessAdapter ? (
                  <>
                    {selectableInterfaces.length > 1 ? (
                      <label className="interface-select">
                        <span>Selected Interface</span>
                        <select
                          onChange={(event) => setSelectedInterfaceName(event.target.value)}
                          value={selectedInterfaceName}
                        >
                          {selectableInterfaces.map((adapter) => {
                            const adapterName = getInterfaceName(adapter)

                            return (
                              <option key={adapterName} value={adapterName}>
                                {adapterName}
                              </option>
                            )
                          })}
                        </select>
                      </label>
                    ) : null}
                    <dl className="status-list">
                      <div>
                        <dt>Adapter Status</dt>
                        <dd>{formatValue(adapterState)}</dd>
                      </div>
                      <div>
                        <dt>Interface Name</dt>
                        <dd>{formatValue(selectedInterface)}</dd>
                      </div>
                      <div>
                        <dt>Mode</dt>
                        <dd>{formatValue(getValue(wirelessAdapter, ['mode']))}</dd>
                      </div>
                      <div>
                        <dt>Channel</dt>
                        <dd>{formatValue(getValue(wirelessAdapter, ['channel']))}</dd>
                      </div>
                    </dl>
                  </>
                ) : (
                  <div className="empty-state">
                    <p>No wireless adapter detected.</p>
                    <p>Connect a compatible monitor-mode WiFi adapter to start scanning.</p>
                  </div>
                )}
              </section>

              <section className="panel scanner-panel">
                <h2>Scanner Status</h2>
                <dl className="status-list scanner-status-list">
                  <div>
                    <dt>Scanner State</dt>
                    <dd>{formatValue(getValue(scannerStatus, ['state', 'scanner_state', 'status']))}</dd>
                  </div>
                  <div>
                    <dt>Interface</dt>
                    <dd>{formatValue(getValue(scannerProgress, ['interface']))}</dd>
                  </div>
                  <div>
                    <dt>Current Channel</dt>
                    <dd>{formatValue(getValue(scannerProgress, ['current_channel']))}</dd>
                  </div>
                  <div>
                    <dt>Sweep Number</dt>
                    <dd>{formatValue(getValue(scannerProgress, ['sweep_number']))}</dd>
                  </div>
                  <div>
                    <dt>Channels Completed</dt>
                    <dd>
                      {formatValue(getValue(scannerProgress, ['channels_completed']))}
                      {' / '}
                      {formatValue(getValue(scannerProgress, ['total_channels']))}
                    </dd>
                  </div>
                  <div>
                    <dt>Networks Discovered</dt>
                    <dd>{formatValue(getValue(scannerProgress, ['session_network_count']))}</dd>
                  </div>
                </dl>
              </section>

              <section className="panel networks-panel">
                <h2>Networks</h2>
                {wifiScanLoading ? (
                  <p className="muted-text">Loading scanned networks...</p>
                ) : networks.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>SSID</th>
                          <th>BSSID</th>
                          <th>Vendor</th>
                          <th>Channel</th>
                          <th>Signal</th>
                          <th>Security</th>
                          <th>Analysis Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {networks.map((network, index) => (
                          <tr key={getValue(network, ['bssid', 'BSSID']) ?? index}>
                            <td>{formatValue(getValue(network, ['ssid', 'SSID']))}</td>
                            <td>{formatValue(getValue(network, ['bssid', 'BSSID']))}</td>
                            <td>{formatValue(getValue(network, ['vendor', 'Vendor']))}</td>
                            <td>{formatValue(getValue(network, ['channel', 'Channel']))}</td>
                            <td>{formatValue(getValue(network, ['signal', 'Signal']))}</td>
                            <td>{formatValue(getValue(network, ['encryption']))}</td>
                            <td>
                              {formatValue(
                                getValue(network, [
                                  'analysis_status',
                                  'analysisStatus',
                                  'Analysis Status',
                                ]),
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="empty-state">No scanned networks are available.</p>
                )}
              </section>
            </section>
          ) : activeView === 'Live Monitor' ? (
            <section className="live-monitor-view" aria-label="Live packet monitor">
              {liveMonitorError ? <p className="error-banner">{liveMonitorError}</p> : null}

              <section className="panel capture-control-panel">
                <div className="panel-header">
                  <h2>Capture Control</h2>
                  <div className="scan-actions">
                    <button
                      className="scan-button primary"
                      disabled={startCaptureDisabled}
                      onClick={handleStartCapture}
                      type="button"
                    >
                      Start Capture
                    </button>
                    <button
                      className="scan-button"
                      disabled={stopCaptureDisabled}
                      onClick={handleStopCapture}
                      type="button"
                    >
                      Stop Capture
                    </button>
                  </div>
                </div>

                {liveMonitorLoading ? (
                  <p className="muted-text">Loading capture controls...</p>
                ) : captureAdapter ? (
                  <>
                    {selectableInterfaces.length > 1 ? (
                      <label className="interface-select">
                        <span>Selected Interface</span>
                        <select
                          onChange={(event) => setSelectedCaptureInterfaceName(event.target.value)}
                          value={selectedCaptureInterfaceName}
                        >
                          {selectableInterfaces.map((adapter) => {
                            const adapterName = getInterfaceName(adapter)

                            return (
                              <option key={adapterName} value={adapterName}>
                                {adapterName}
                              </option>
                            )
                          })}
                        </select>
                      </label>
                    ) : null}
                    <dl className="status-list capture-control-list">
                      <div>
                        <dt>Capture State</dt>
                        <dd>{formatValue(getValue(captureStatus, ['state', 'capture_state', 'status']))}</dd>
                      </div>
                      <div>
                        <dt>Interface</dt>
                        <dd>
                          {formatValue(
                            getValue(captureStatus, ['interface', 'interface_name']) ??
                              getValue(captureProgress, ['interface']) ??
                              selectedCaptureInterface,
                          )}
                        </dd>
                      </div>
                      <div>
                        <dt>Mode</dt>
                        <dd>{formatValue(getValue(captureStatus, ['mode']) ?? getValue(captureAdapter, ['mode']))}</dd>
                      </div>
                      <div>
                        <dt>PID</dt>
                        <dd>{formatValue(getValue(captureStatus, ['pid', 'process_id']))}</dd>
                      </div>
                    </dl>
                  </>
                ) : (
                  <div className="empty-state">
                    <p>No wireless adapter detected.</p>
                    <p>Connect a compatible monitor-mode WiFi adapter to start capture.</p>
                  </div>
                )}
              </section>

              <section className="panel capture-stats-panel">
                <h2>Live Capture Statistics</h2>
                <dl className="status-list capture-stats-list">
                  <div>
                    <dt>Session Packets</dt>
                    <dd>{formatValue(getValue(captureProgress, ['packet_count']))}</dd>
                  </div>
                  <div>
                    <dt>Packet Rate</dt>
                    <dd>{formatWithUnit(getValue(captureProgress, ['packet_rate']), 'pkt/s')}</dd>
                  </div>
                  <div>
                    <dt>Current Channel</dt>
                    <dd>{formatValue(getValue(captureProgress, ['current_channel']))}</dd>
                  </div>
                  <div>
                    <dt>Channel Sweep</dt>
                    <dd>
                      {formatValue(getValue(captureProgress, ['channel_index']))}
                      {' / '}
                      {formatValue(getValue(captureProgress, ['total_channels']))}
                    </dd>
                  </div>
                  <div>
                    <dt>Sweep Number</dt>
                    <dd>{formatValue(getValue(captureProgress, ['sweep_number']))}</dd>
                  </div>
                  <div>
                    <dt>Elapsed Time</dt>
                    <dd>{formatWithUnit(getValue(captureProgress, ['elapsed_seconds']), 'seconds')}</dd>
                  </div>
                  <div>
                    <dt>Last Packet</dt>
                    <dd>{formatValue(getValue(captureProgress, ['last_packet_at']))}</dd>
                  </div>
                </dl>

                <div className="packet-counts">
                  <p className="section-label">Packet Type Counts</p>
                  {Object.keys(packetTypeCounts).length > 0 ? (
                    <div className="count-grid">
                      {Object.entries(packetTypeCounts).map(([packetType, count]) => (
                        <div className="count-pill" key={packetType}>
                          <span>{packetType}</span>
                          <strong>{formatValue(count)}</strong>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="muted-text">No packet type counts reported yet.</p>
                  )}
                </div>
              </section>

              <section className="panel packets-panel">
                <h2>Recent Packets</h2>
                {liveMonitorLoading ? (
                  <p className="muted-text">Loading recent packets...</p>
                ) : packets.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Packet Type</th>
                          <th>Source MAC</th>
                          <th>Destination MAC</th>
                          <th>BSSID</th>
                          <th>Frame Type</th>
                          <th>Signal</th>
                        </tr>
                      </thead>
                      <tbody>
                        {packets.map((packet, index) => (
                          <tr key={getValue(packet, ['id', 'packet_id']) ?? index}>
                            <td>{formatValue(getValue(packet, ['time', 'timestamp', 'captured_at']))}</td>
                            <td>{formatValue(getValue(packet, ['packet_type', 'type', 'classification']))}</td>
                            <td>{formatValue(getValue(packet, ['source_mac', 'src_mac', 'source']))}</td>
                            <td>
                              {formatValue(
                                getValue(packet, ['destination_mac', 'dst_mac', 'destination']),
                              )}
                            </td>
                            <td>{formatValue(getValue(packet, ['bssid']))}</td>
                            <td>{formatValue(getValue(packet, ['frame_type', 'frame']))}</td>
                            <td>{formatWithUnit(getValue(packet, ['signal_strength']), 'dBm')}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="empty-state">No captured packets are available.</p>
                )}
              </section>
            </section>
          ) : activeView === 'ML Detection' ? (
            <section className="ml-detection-view" aria-label="ML Detection">
              {mlDetectionError ? <p className="error-banner">{mlDetectionError}</p> : null}

              <section className="panel">
                <h2>Live V3 Random Forest Inference</h2>
                <p className="muted-text">
                  Results are refreshed every 2 seconds from completed 5-second live packet capture windows.
                </p>

                {mlDetectionLoading ? (
                  <p className="muted-text">Loading ML inference status...</p>
                ) : mlLiveStatus?.status === 'no_inference' || mlLiveStatus === null ? (
                  <p className="empty-state">
                    Waiting for the first completed 5-second inference window. Start live packet
                    capture to begin ML detection.
                  </p>
                ) : (
                  <>
                    <div className="metric-grid">
                      <article
                        className="metric-card"
                        style={{
                          borderTop: mlLiveStatus.prediction === 0
                            ? '3px solid #22c55e'
                            : '3px solid #ef4444',
                        }}
                      >
                        <p>Label</p>
                        <strong>{mlLiveStatus.label ?? 'Unknown'}</strong>
                      </article>

                      <article className="metric-card">
                        <p>Prediction</p>
                        <strong>{mlLiveStatus.prediction ?? '--'}</strong>
                      </article>

                      <article className="metric-card">
                        <p>Attack Probability</p>
                        <strong>
                          {mlLiveStatus.attack_probability !== undefined
                            ? `${(mlLiveStatus.attack_probability * 100).toFixed(1)}%`
                            : '--'}
                        </strong>
                      </article>

                      <article className="metric-card">
                        <p>Normal Probability</p>
                        <strong>
                          {mlLiveStatus.normal_probability !== undefined
                            ? `${(mlLiveStatus.normal_probability * 100).toFixed(1)}%`
                            : '--'}
                        </strong>
                      </article>
                    </div>

                    <dl className="status-list">
                      <div>
                        <dt>Total Packets in Window</dt>
                        <dd>{formatValue(mlLiveStatus.total_packets)}</dd>
                      </div>
                      <div>
                        <dt>Feature Count</dt>
                        <dd>{formatValue(mlLiveStatus.feature_count)}</dd>
                      </div>
                      <div>
                        <dt>Window Start</dt>
                        <dd>{formatValue(mlLiveStatus.window_start)}</dd>
                      </div>
                      <div>
                        <dt>Window End</dt>
                        <dd>{formatValue(mlLiveStatus.window_end)}</dd>
                      </div>
                    </dl>
                  </>
                )}
              </section>
            </section>
          ) : activeView === 'Incidents' ? (
            <section className="incidents-view" aria-label="Security Incidents">
              {incidentsError ? <p className="error-banner">{incidentsError}</p> : null}

              <div className="metric-grid">
                <article className="metric-card">
                  <p>Total Incidents</p>
                  <strong>{totalIncidents}</strong>
                </article>
                <article className="metric-card">
                  <p>New Incidents</p>
                  <strong>{newIncidents}</strong>
                </article>
                <article className="metric-card">
                  <p>High Severity</p>
                  <strong>{highSeverityIncidents}</strong>
                </article>
              </div>

              <section className="panel incidents-panel">
                <h2>Security Incidents</h2>
                <p className="muted-text">
                  ML attack detections recorded from completed live inference windows.
                </p>

                {incidentsLoading ? (
                  <p className="muted-text">Loading incidents...</p>
                ) : incidents.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Time</th>
                          <th>Detection</th>
                          <th>Attack Probability</th>
                          <th>Packets</th>
                          <th>Severity</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {incidents.map((incident, index) => (
                          <tr key={getValue(incident, ['id']) ?? index}>
                            <td>{formatValue(incident.id)}</td>
                            <td>{formatDateTime(incident.created_at)}</td>
                            <td>
                              <span className="badge badge-detection">
                                {formatValue(incident.label ?? incident.prediction)}
                              </span>
                            </td>
                            <td>{formatProbability(incident.attack_probability)}</td>
                            <td>{formatValue(incident.total_packets)}</td>
                            <td>
                              <span className={getSeverityBadgeClass(incident.severity)}>
                                {formatValue(incident.severity)}
                              </span>
                            </td>
                            <td>
                              <span className={getStatusBadgeClass(incident.status)}>
                                {formatValue(incident.status)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state">
                    <p>No incidents detected</p>
                    <p>Incidents created by ML attack detections will appear here.</p>
                  </div>
                )}
              </section>
            </section>
          ) : activeView === 'Reports' ? (
            <section className="reports-view" aria-label="Security reports">
              {reportsError ? <p className="error-banner">{reportsError}</p> : null}

              <div className="reports-header-panel panel">
                <div className="panel-header">
                  <div>
                    <h2>Security Reports</h2>
                    <p className="panel-subtitle">
                      Incident telemetry and analytical summary generated from real-time ML intrusion detections.
                    </p>
                  </div>
                  <div className="report-controls">
                    <button
                      className="scan-button"
                      disabled={reportsLoading}
                      onClick={handleRefreshReports}
                      type="button"
                    >
                      {reportsLoading ? 'Refreshing...' : 'Refresh Reports'}
                    </button>
                    <button
                      className="scan-button"
                      disabled={reportsLoading || reportIncidents.length === 0}
                      onClick={handleExportCsv}
                      type="button"
                    >
                      Export CSV
                    </button>
                    <button
                      className="scan-button primary"
                      disabled={reportsLoading}
                      onClick={() => window.print()}
                      type="button"
                    >
                      Print / Save PDF
                    </button>
                  </div>
                </div>
              </div>

              <div className="metric-grid">
                <article className="metric-card">
                  <p>Total Incidents</p>
                  <strong>{reportTotalIncidents}</strong>
                </article>
                <article className="metric-card">
                  <p>High Severity</p>
                  <strong>{reportHighSeverity}</strong>
                </article>
                <article className="metric-card">
                  <p>Packets in Incidents</p>
                  <strong>{reportTotalPackets}</strong>
                </article>
                <article className="metric-card">
                  <p>Average Attack Probability</p>
                  <strong>{reportAvgAttackProb !== null ? formatProbability(reportAvgAttackProb) : '--'}</strong>
                </article>
              </div>

              <section className="panel attack-summary-panel">
                <div className="panel-header">
                  <h2>Attack Summary</h2>
                </div>
                {Object.keys(attackCountsByLabel).length > 0 ? (
                  <div className="attack-summary-grid">
                    {Object.entries(attackCountsByLabel).map(([label, count]) => (
                      <div className="attack-summary-item" key={label}>
                        <span className="badge badge-detection">{label}</span>
                        <span className="attack-count">{count} {count === 1 ? 'incident' : 'incidents'}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="empty-state-muted">No attacks recorded yet.</p>
                )}
              </section>

              <section className="panel incidents-report-panel">
                <div className="panel-header">
                  <h2>Incident Report</h2>
                </div>
                {reportsLoading ? (
                  <p className="muted-text">Loading reports data...</p>
                ) : reportIncidents.length > 0 ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Date/Time</th>
                          <th>Attack Label</th>
                          <th>Attack Probability</th>
                          <th>Packets</th>
                          <th>Severity</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {reportIncidents.map((incident, index) => (
                          <tr key={getValue(incident, ['id']) ?? index}>
                            <td>{formatValue(incident.id)}</td>
                            <td>{formatDateTime(incident.created_at)}</td>
                            <td>
                              <span className="badge badge-detection">
                                {formatValue(incident.label ?? incident.prediction)}
                              </span>
                            </td>
                            <td>{formatProbability(incident.attack_probability)}</td>
                            <td>{formatValue(incident.total_packets)}</td>
                            <td>
                              <span className={getSeverityBadgeClass(incident.severity)}>
                                {formatValue(incident.severity)}
                              </span>
                            </td>
                            <td>
                              <span className={getStatusBadgeClass(incident.status)}>
                                {formatValue(incident.status)}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="empty-state">
                    <p>No security incidents recorded yet. Reports will populate when the ML detector identifies an attack.</p>
                  </div>
                )}
              </section>
            </section>
          ) : (
            <section className="placeholder-view">
              <p className="eyebrow">{activeView}</p>
              <h2>{activeView}</h2>
              <p>This section is ready for future NetShield functionality.</p>
            </section>
          )}
        </main>
      </div>
    </div>
  )
}

export default App
