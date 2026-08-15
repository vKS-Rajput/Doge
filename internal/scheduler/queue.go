package scheduler

import (
	"fmt"
	"sort"
	"sync"
)

// JobQueue is a priority-ordered, bounded queue of jobs.
//
// Priority ordering: critical > high > normal > low.
// Bounded: rejects when full (backpressure, not crash).
// Deduplication: same tool + same target = skip.
type JobQueue struct {
	jobs    []Job
	maxSize int
	mu      sync.Mutex
}

// NewJobQueue creates a bounded job queue.
func NewJobQueue(maxSize int) *JobQueue {
	if maxSize <= 0 {
		maxSize = 50
	}
	return &JobQueue{
		jobs:    make([]Job, 0),
		maxSize: maxSize,
	}
}

// Enqueue adds a job to the queue. Returns error if full or duplicate.
func (q *JobQueue) Enqueue(job Job) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.jobs) >= q.maxSize {
		return fmt.Errorf("job queue full (%d/%d)", len(q.jobs), q.maxSize)
	}

	// Deduplicate: same tool + same target that isn't terminal.
	for _, existing := range q.jobs {
		if existing.Tool == job.Tool &&
			existing.Target == job.Target &&
			!existing.Status.IsTerminal() {
			return fmt.Errorf("duplicate job: %s targeting %s already queued", job.Tool, job.Target)
		}
	}

	q.jobs = append(q.jobs, job)
	q.sortByPriority()
	return nil
}

// Dequeue removes and returns the highest-priority queued job.
// Returns nil if no queued jobs are available.
func (q *JobQueue) Dequeue() *Job {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i, job := range q.jobs {
		if job.Status == JobQueued {
			q.jobs[i].Status = JobRunning
			j := q.jobs[i]
			return &j
		}
	}
	return nil
}

// Update modifies a job in the queue by ID.
func (q *JobQueue) Update(job Job) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i, existing := range q.jobs {
		if existing.ID == job.ID {
			q.jobs[i] = job
			return
		}
	}
}

// Len returns the number of jobs in the queue.
func (q *JobQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.jobs)
}

// Queued returns the number of jobs awaiting execution.
func (q *JobQueue) Queued() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := 0
	for _, j := range q.jobs {
		if j.Status == JobQueued {
			count++
		}
	}
	return count
}

// Running returns the number of currently executing jobs.
func (q *JobQueue) Running() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := 0
	for _, j := range q.jobs {
		if j.Status == JobRunning {
			count++
		}
	}
	return count
}

// All returns a snapshot of all jobs.
func (q *JobQueue) All() []Job {
	q.mu.Lock()
	defer q.mu.Unlock()
	result := make([]Job, len(q.jobs))
	copy(result, q.jobs)
	return result
}

// ByStatus returns jobs with a specific status.
func (q *JobQueue) ByStatus(status JobStatus) []Job {
	q.mu.Lock()
	defer q.mu.Unlock()
	var result []Job
	for _, j := range q.jobs {
		if j.Status == status {
			result = append(result, j)
		}
	}
	return result
}

// RunningForTool returns how many instances of a tool are running.
func (q *JobQueue) RunningForTool(tool string) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := 0
	for _, j := range q.jobs {
		if j.Tool == tool && j.Status == JobRunning {
			count++
		}
	}
	return count
}

// Cleanup removes terminal jobs older than the cutoff.
func (q *JobQueue) Cleanup(keepLast int) {
	q.mu.Lock()
	defer q.mu.Unlock()

	var active, completed []Job
	for _, j := range q.jobs {
		if j.Status.IsTerminal() {
			completed = append(completed, j)
		} else {
			active = append(active, j)
		}
	}

	if len(completed) > keepLast {
		completed = completed[len(completed)-keepLast:]
	}

	q.jobs = append(active, completed...)
}

func (q *JobQueue) sortByPriority() {
	sort.SliceStable(q.jobs, func(i, j int) bool {
		// Non-terminal before terminal.
		if !q.jobs[i].Status.IsTerminal() && q.jobs[j].Status.IsTerminal() {
			return true
		}
		if q.jobs[i].Status.IsTerminal() && !q.jobs[j].Status.IsTerminal() {
			return false
		}
		// Higher priority (lower number) first.
		return q.jobs[i].Priority < q.jobs[j].Priority
	})
}
