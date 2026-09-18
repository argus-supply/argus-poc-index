"""Project thresholds are measurements and warnings, never admission rules."""
import logging


def threshold_observation(metric, observed, threshold):
    """Return a serializable measurement and warn when its target is exceeded."""
    result = {'metric': metric, 'observed': observed, 'threshold': threshold,
              'exceeded': observed > threshold, 'enforcement': 'advisory'}
    if result['exceeded']:
        logging.getLogger(__name__).warning('project threshold exceeded: %s=%s target=%s',
                                           metric, observed, threshold)
    return result
